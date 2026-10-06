//go:build linux

package executor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const integrityWatchLimit = 4096
const integrityEventMask = unix.IN_CLOSE_WRITE | unix.IN_ATTRIB | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR | unix.IN_DONT_FOLLOW

type integrityWatchPlan struct {
	ID       string
	SyncID   string
	Policy   moduleIntegrityPolicy
	Excludes []string
}
type integrityWatchSite struct {
	Plans       []integrityWatchPlan
	Fingerprint string
	Root        os.FileInfo
	Watches     map[int]bool
	State       string
	Error       string
	Rebuild     bool
	RetryAt     time.Time
}
type integrityDirtySite struct {
	First   time.Time
	Due     time.Time
	Trigger string
}

// Only this goroutine owns the inotify descriptor and watch maps. Kernel names
// are deliberately not decoded into paths: checks always reopen the managed
// site and compare its signed baseline, rather than trusting an event payload.
type integrityWatcher struct {
	Service   *Service
	FD        int
	Limit     int
	Sites     map[string]*integrityWatchSite
	Watches   map[int]map[string]bool
	Dirty     map[string]integrityDirtySite
	Overflows uint64
	InitError string
}

func (s *Service) wakeIntegrityWatcher() {
	if s.moduleWatchWake != nil {
		select {
		case s.moduleWatchWake <- struct{}{}:
		default:
		}
	}
}

func (s *Service) runIntegrityWatcher(ctx context.Context) {
	w := &integrityWatcher{Service: s, FD: -1, Limit: integrityWatchLimit, Sites: map[string]*integrityWatchSite{}, Watches: map[int]map[string]bool{}, Dirty: map[string]integrityDirtySite{}}
	defer w.close()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	reconcileAt, retryAt := time.Time{}, time.Time{}
	for {
		now := time.Now()
		if w.FD < 0 && !retryAt.After(now) {
			fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
			if err != nil {
				w.InitError = "实时监听不可用，保留定时补查：" + err.Error()
				retryAt = now.Add(30 * time.Second)
			} else {
				w.FD, w.InitError = fd, ""
				for _, site := range w.Sites {
					site.Rebuild = true
				}
			}
		}
		if !reconcileAt.After(now) {
			w.reconcile(ctx, now)
			reconcileAt = now.Add(2 * time.Second)
		}
		if w.drain(now) {
			// Reconcile dynamic directories promptly; the full baseline check
			// also closes the gap for files created before a watch was added.
			reconcileAt = time.Time{}
		}
		w.flush(now)
		select {
		case <-ctx.Done():
			return
		case <-s.moduleWatchWake:
			reconcileAt = time.Time{}
		case <-ticker.C:
		}
	}
}

func (w *integrityWatcher) close() {
	if w.FD >= 0 {
		_ = unix.Close(w.FD)
		w.FD = -1
	}
	w.Service.mu.Lock()
	for key, status := range w.Service.moduleWatchStatus {
		status.State = "stopped"
		status.Directories = 0
		status.UpdatedAt = core.Now()
		w.Service.moduleWatchStatus[key] = status
	}
	w.Service.mu.Unlock()
}

func (w *integrityWatcher) desired() map[string][]integrityWatchPlan {
	s := w.Service
	s.mu.Lock()
	defer s.mu.Unlock()
	result := map[string][]integrityWatchPlan{}
	for _, id := range []string{"file-monitor", "website-tamper-proof", "enterprise-tamper-proof"} {
		if !s.moduleInstalled(id) {
			continue
		}
		paths, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "baselines", "*", "baseline.json"))
		sort.Strings(paths)
		if len(paths) > 100 {
			paths = paths[:100]
		}
		for _, path := range paths {
			site := filepath.Base(filepath.Dir(path))
			if !core.ValidID(site) {
				continue
			}
			policy, err := s.readIntegrityPolicy(id, site)
			if err == nil && policy.Enabled && policy.Realtime && !s.moduleAutoBlocked[id+"/"+site] {
				result[site] = append(result[site], integrityWatchPlan{ID: id, Policy: policy})
			}
		}
	}
	if s.moduleInstalled("files-sync") {
		plans, _ := s.readSyncPlans()
		for _, plan := range plans {
			if plan.Enabled && plan.Realtime && !s.moduleAutoBlocked["files-sync/"+plan.ID] {
				result[plan.SiteID] = append(result[plan.SiteID], integrityWatchPlan{ID: "files-sync", SyncID: plan.ID, Policy: moduleIntegrityPolicy{Revision: plan.Revision}, Excludes: plan.Excludes})
			}
		}
	}
	return result
}

func watchFingerprint(plans []integrityWatchPlan) string {
	parts := []string{}
	for _, plan := range plans {
		parts = append(parts, fmt.Sprintf("%s:%s:%d", plan.ID, plan.SyncID, plan.Policy.Revision))
	}
	return strings.Join(parts, ",")
}

func (s *Service) openIntegrityWatchFiles(site string) (*siteFiles, os.FileInfo, error) {
	f, err := s.openFiles(site)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*siteFiles, os.FileInfo, error) { f.Close(); return nil, nil, err }
	base, err := os.OpenRoot(s.Config.SitesDir)
	if err != nil {
		return fail(err)
	}
	siteInfo, err := base.Lstat(site)
	base.Close()
	rootInfo, rootErr := f.root.Stat(".")
	publicInfo, publicErr := f.root.Lstat("public")
	info, statErr := f.public.Stat(".")
	if err != nil || rootErr != nil || publicErr != nil || statErr != nil || !siteInfo.IsDir() || !publicInfo.IsDir() || !os.SameFile(siteInfo, rootInfo) || !os.SameFile(publicInfo, info) {
		return fail(errors.New("网站根目录发生变化或包含链接，实时监听未启用"))
	}
	return f, info, nil
}

func (w *integrityWatcher) drop(site string) {
	state := w.Sites[site]
	if state == nil {
		return
	}
	for wd := range state.Watches {
		owners := w.Watches[wd]
		delete(owners, site)
		if len(owners) == 0 {
			delete(w.Watches, wd)
			if w.FD >= 0 {
				_, _ = unix.InotifyRmWatch(w.FD, uint32(wd))
			}
		}
	}
	state.Watches = map[int]bool{}
}

func (w *integrityWatcher) reconcile(ctx context.Context, now time.Time) {
	desired := w.desired()
	for site := range w.Sites {
		if _, ok := desired[site]; !ok {
			w.drop(site)
			delete(w.Sites, site)
			delete(w.Dirty, site)
		}
	}
	ids := []string{}
	for site := range desired {
		ids = append(ids, site)
	}
	sort.Strings(ids)
	for _, site := range ids {
		if ctx.Err() != nil {
			break
		}
		plans := desired[site]
		fingerprint := watchFingerprint(plans)
		state := w.Sites[site]
		if state == nil {
			state = &integrityWatchSite{Watches: map[int]bool{}, Rebuild: true}
			w.Sites[site] = state
		}
		if state.Fingerprint != fingerprint {
			state.Plans, state.Fingerprint, state.Rebuild = plans, fingerprint, true
			state.RetryAt = time.Time{}
		}
		if w.FD < 0 {
			state.State, state.Error = "unavailable", w.InitError
			continue
		}
		f, info, err := w.Service.openIntegrityWatchFiles(site)
		if err != nil {
			w.drop(site)
			state.State, state.Error, state.Rebuild = "degraded", err.Error(), true
			state.RetryAt = now.Add(10 * time.Second)
			continue
		}
		if state.Root == nil || !os.SameFile(info, state.Root) {
			state.Rebuild = true
			state.RetryAt = time.Time{}
		}
		if state.Rebuild && !state.RetryAt.After(now) {
			w.drop(site)
			state.Root, state.Error, state.State = info, "", "active"
			// Verify only on setup/configuration changes, not every polling
			// tick. The actual check verifies the signature again every time.
			w.Service.mu.Lock()
			for i := range state.Plans {
				if state.Plans[i].SyncID != "" {
					continue
				}
				baseline, baselineErr := w.Service.readIntegrityBaseline(state.Plans[i].ID, site)
				if baselineErr != nil {
					err = baselineErr
					break
				}
				state.Plans[i].Excludes = baseline.Excludes
			}
			w.Service.mu.Unlock()
			if err == nil {
				err = w.watchTree(ctx, site, state, f)
			}
			state.Rebuild = err != nil
			if err != nil {
				state.State, state.Error = "degraded", err.Error()
				state.RetryAt = now.Add(10 * time.Second)
			} else {
				state.RetryAt = time.Time{}
			}
			w.markDirty(site, "inotify-reconcile", now)
		}
		f.Close()
	}
	w.publish()
}

func watchExcluded(path string, plans []integrityWatchPlan) bool {
	for _, plan := range plans {
		excluded := false
		for _, prefix := range plan.Excludes {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				excluded = true
				break
			}
		}
		if !excluded {
			return false
		}
	}
	return len(plans) > 0
}

func (w *integrityWatcher) watchTree(ctx context.Context, site string, state *integrityWatchSite, f *siteFiles) error {
	queue, entries := []string{"."}, 0
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel := queue[0]
		queue = queue[1:]
		dir, err := f.public.OpenFile(rel, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return errors.New("目录在建立监听时变化，保留定时补查")
		}
		info, statErr := dir.Stat()
		current, pathErr := f.public.Lstat(rel)
		if statErr != nil || pathErr != nil || !current.IsDir() || !os.SameFile(info, current) {
			dir.Close()
			return errors.New("监听目录身份发生变化")
		}
		if len(w.Watches) >= w.Limit {
			dir.Close()
			return fmt.Errorf("实时目录监听达到 %d 个上限，部分目录仅定时补查", w.Limit)
		}
		// /proc/self/fd/N/. anchors the directory inode without trusting a
		// pathname whose ancestors could be renamed after validation.
		wd, err := unix.InotifyAddWatch(w.FD, fmt.Sprintf("/proc/self/fd/%d/.", dir.Fd()), integrityEventMask)
		if err != nil {
			dir.Close()
			return errors.New("内核目录监听失败，保留定时补查：" + err.Error())
		}
		if w.Watches[wd] == nil {
			w.Watches[wd] = map[string]bool{}
		}
		w.Watches[wd][site], state.Watches[wd] = true, true
		for {
			batch, readErr := dir.ReadDir(256)
			for _, entry := range batch {
				entries++
				if entries > 100000 {
					dir.Close()
					return errors.New("实时目录遍历超过 100000 个条目，保留定时补查")
				}
				path := filepath.Join(rel, entry.Name())
				if watchExcluded(path, state.Plans) {
					continue
				}
				if entry.Type()&os.ModeSymlink != 0 {
					dir.Close()
					return errors.New("监控范围包含符号链接，请配置排除路径")
				}
				if entry.IsDir() {
					if !core.ValidFilePath(path, false) {
						dir.Close()
						return errors.New("监控范围包含不支持的目录名")
					}
					queue = append(queue, path)
					if len(queue)+len(state.Watches) > w.Limit {
						dir.Close()
						return fmt.Errorf("实时目录监听达到 %d 个上限，部分目录仅定时补查", w.Limit)
					}
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					dir.Close()
					return errors.New("监听目录读取失败，保留定时补查")
				}
				break
			}
		}
		dir.Close()
	}
	return nil
}

func (w *integrityWatcher) publish() {
	s := w.Service
	s.mu.Lock()
	defer s.mu.Unlock()
	statuses := map[string]moduleRealtimeStatus{}
	for site, state := range w.Sites {
		for _, plan := range state.Plans {
			key := plan.ID + "/" + site
			if plan.SyncID != "" {
				key = plan.ID + "/" + plan.SyncID
			}
			statuses[key] = moduleRealtimeStatus{State: state.State, Directories: len(state.Watches), Error: state.Error, Overflows: w.Overflows, UpdatedAt: core.Now()}
		}
	}
	s.moduleWatchStatus = statuses
}

func (w *integrityWatcher) markDirty(site, trigger string, now time.Time) {
	value, exists := w.Dirty[site]
	if !exists {
		value.First = now
	}
	// Debounce file bursts, but sustained traffic cannot postpone a check
	// indefinitely. Overflow is retained as the stronger trigger.
	value.Due = now.Add(500 * time.Millisecond)
	if value.First.Add(2 * time.Second).Before(value.Due) {
		value.Due = value.First.Add(2 * time.Second)
	}
	if value.Trigger != "inotify-overflow" {
		value.Trigger = trigger
	}
	w.Dirty[site] = value
}

func (w *integrityWatcher) overflow(now time.Time) {
	w.Overflows++
	for site, state := range w.Sites {
		state.Rebuild = true
		state.RetryAt = time.Time{}
		w.markDirty(site, "inotify-overflow", now)
	}
	w.publish()
}

func (w *integrityWatcher) consume(raw []byte, now time.Time) bool {
	rebuild := false
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < unix.SizeofInotifyEvent {
			w.overflow(now)
			return true
		}
		wd := int(int32(binary.NativeEndian.Uint32(raw[offset:])))
		mask := binary.NativeEndian.Uint32(raw[offset+4:])
		nameLength := int(binary.NativeEndian.Uint32(raw[offset+12:]))
		if nameLength > len(raw)-offset-unix.SizeofInotifyEvent {
			w.overflow(now)
			return true
		}
		offset += unix.SizeofInotifyEvent + nameLength
		if mask&unix.IN_Q_OVERFLOW != 0 {
			w.overflow(now)
			rebuild = true
			continue
		}
		for site := range w.Watches[wd] {
			state := w.Sites[site]
			if state == nil {
				continue
			}
			w.markDirty(site, "inotify", now)
			if mask&(unix.IN_IGNORED|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 || mask&unix.IN_ISDIR != 0 {
				state.Rebuild = true
				state.RetryAt = time.Time{}
				rebuild = true
			}
		}
		if mask&unix.IN_IGNORED != 0 {
			for site := range w.Watches[wd] {
				delete(w.Sites[site].Watches, wd)
			}
			delete(w.Watches, wd)
		}
	}
	return rebuild
}

func (w *integrityWatcher) drain(now time.Time) bool {
	if w.FD < 0 {
		return false
	}
	buffer := make([]byte, 64<<10)
	rebuild := false
	for i := 0; i < 32; i++ {
		n, err := unix.Read(w.FD, buffer)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			w.InitError = "实时事件读取失败，保留定时补查"
			_ = unix.Close(w.FD)
			w.FD = -1
			w.Watches = map[int]map[string]bool{}
			for _, state := range w.Sites {
				state.Watches, state.Rebuild = map[int]bool{}, true
			}
			return true
		}
		if w.consume(buffer[:n], now) {
			rebuild = true
		}
	}
	return rebuild
}

func (w *integrityWatcher) flush(now time.Time) {
	ids := []string{}
	for site, dirty := range w.Dirty {
		if !dirty.Due.After(now) {
			ids = append(ids, site)
		}
	}
	sort.Strings(ids)
	// Bound work per tick. Expensive baseline scans cannot create an
	// unbounded event queue; subsequent kernel events coalesce by site.
	if len(ids) > 2 {
		ids = ids[:2]
	}
	for _, site := range ids {
		dirty := w.Dirty[site]
		delete(w.Dirty, site)
		state := w.Sites[site]
		if state == nil {
			continue
		}
		for _, plan := range state.Plans {
			s := w.Service
			s.mu.Lock()
			if plan.SyncID != "" {
				var fresh moduleSyncPlan
				if moduleRead(s.syncPlanPath(plan.SyncID), &fresh) == nil && validateSyncPlan(fresh) == nil && fresh.ID == plan.SyncID && fresh.SiteID == site && fresh.Enabled && fresh.Realtime && fresh.Revision == plan.Policy.Revision && !s.moduleAutoBlocked["files-sync/"+plan.SyncID] {
					next, _ := time.Parse(time.RFC3339, fresh.NextRunAt)
					if fresh.FailureCount == 0 || !next.After(now) {
						ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
						result, err := s.executeSyncPlan(ctx, &fresh, dirty.Trigger, now)
						cancel()
						if fresh.Copied != 0 || fresh.Conflicts != 0 || err != nil || dirty.Trigger == "inotify-overflow" {
							report := map[string]any{"time": core.Now(), "action": "realtime-sync", "result": result}
							if err != nil {
								report["error"] = err.Error()
							}
							if moduleWrite(filepath.Join(s.moduleDir("files-sync"), "last-report.json"), report) != nil {
								s.blockModuleAutomation("files-sync/" + plan.SyncID)
							}
						}
					}
				}
				s.mu.Unlock()
				continue
			}
			policy, err := s.readIntegrityPolicy(plan.ID, site)
			next, _ := time.Parse(time.RFC3339, policy.NextRunAt)
			if err == nil && policy.Enabled && policy.Realtime && policy.Revision == plan.Policy.Revision && !s.moduleAutoBlocked[plan.ID+"/"+site] && (policy.FailureCount == 0 || !next.After(now)) {
				s.runIntegrityPolicy(plan.ID, site, policy, dirty.Trigger)
			}
			s.mu.Unlock()
		}
	}
}
