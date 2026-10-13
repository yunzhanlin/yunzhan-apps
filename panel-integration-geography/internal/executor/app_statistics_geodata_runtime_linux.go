//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
	"local/panel/internal/upgradeguard"
)

const statisticsGeoInstanceLock = "/var/lib/panel-executor/statistics-geodata-instance.lock"

func statisticsGeoInstanceLease(exclusive bool) (*os.File, error) {
	if os.Geteuid() != 0 || statisticsGeoParents(filepath.Dir(statisticsGeoInstanceLock)) != nil {
		return nil, errors.New("地域实例锁环境不受信")
	}
	f, err := os.OpenFile(statisticsGeoInstanceLock, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = os.OpenFile(statisticsGeoInstanceLock, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	visible, verr := os.Lstat(statisticsGeoInstanceLock)
	if err != nil || verr != nil || !moduleRecordInfo(opened, false, false) || !moduleRecordInfo(visible, false, false) || !geoStoreStableInfo(opened, visible) || opened.Size() != 0 {
		f.Close()
		return nil, errors.New("地域实例锁身份异常")
	}
	mode := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		mode = unix.LOCK_EX | unix.LOCK_NB
	}
	if unix.Flock(int(f.Fd()), mode) != nil {
		f.Close()
		return nil, errors.New("地域数据与应用生命周期操作不能并行，请核对原任务")
	}
	return f, nil
}
func (s *Service) statisticsGeoInstance() (string, error) {
	installed, err := s.moduleInstalledRecord("website-statistics-v2")
	if err != nil {
		return "", err
	}
	id, ok := installed["installation_id"].(string)
	if installed["version"] != statisticsGeographyVersion || !ok || !core.ValidID(id) {
		return "", errors.New("统计地域只允许明确安装或升级的2.6实例")
	}
	return id, nil
}

// A report leases one immutable verified snapshot for its whole accumulator.
// Updates/reloads never close a reader midway through an existing report.
func (s *Service) statisticsGeoSnapshotLease() (analyticsGeoLookup, func(), bool, string) {
	instance, err := s.statisticsGeoInstance()
	if err != nil {
		return nil, func() {}, false, ""
	}
	s.geoCache.mu.RLock()
	if s.geoCache.instance != instance {
		s.geoCache.mu.RUnlock()
		return nil, func() {}, true, "地域库尚未完成该安装实例的后台核对"
	}
	if s.geoCache.snapshot == nil {
		message := s.geoCache.error
		s.geoCache.mu.RUnlock()
		return nil, func() {}, true, message
	}
	return s.geoCache.snapshot, func() { s.geoCache.mu.RUnlock() }, true, s.geoCache.error
}
func (s *Service) statisticsGeoState() (core.StatisticsGeoState, error) {
	out := core.StatisticsGeoState{Stored: []core.StatisticsGeoStored{}, AppVersion: "", CheckedAt: core.Now()}
	record, err := s.moduleInstalledRecord("website-statistics-v2")
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Installed = true
	out.AppVersion, _ = record["version"].(string)
	if out.AppVersion != statisticsGeographyVersion {
		return out, nil
	}
	instance, err := s.statisticsGeoInstance()
	if err != nil {
		return out, err
	}
	out.InstallationID = instance
	s.geoCache.mu.RLock()
	if s.geoCache.instance == instance {
		out.Metadata = s.geoCache.snapshot.Metadata(time.Now())
		out.Loading = s.geoCache.loading
		out.Error = s.geoCache.error
		out.CheckedAt = s.geoCache.checkedAt
	}
	s.geoCache.mu.RUnlock()
	store, err := s.statisticsGeoDataStore()
	if err != nil {
		return out, err
	}
	root, err := store.open(false)
	if errors.Is(err, os.ErrNotExist) {
		archive, names, archiveErr := store.archivedInventory()
		if archive != nil {
			archive.Close()
		}
		if archiveErr != nil || len(names) > 0 {
			return out, errors.New("活动数据目录缺失但归档状态不可核对；未隐藏原副本或猜测防重放记录")
		}
		return out, nil
	}
	if err != nil {
		return out, err
	}
	defer root.Close()
	selected, _, _, err := store.selector(root.Root)
	if err != nil {
		return out, err
	}
	out.Selected = selected.Dataset
	out.Stored, err = store.storedRows(root, selected)
	return out, err
}
func (s *Service) refreshStatisticsGeoCache(ctx context.Context) {
	if ctx == nil || ctx.Err() != nil || upgradeguard.Blocked() {
		return
	}
	instance, err := s.statisticsGeoInstance()
	if err != nil {
		s.geoCache.mu.Lock()
		old := s.geoCache.snapshot
		s.geoCache.snapshot = nil
		s.geoCache.instance = ""
		s.geoCache.selected = ""
		s.geoCache.selectorRaw = nil
		s.geoCache.fallbackRaw = nil
		s.geoCache.loading = false
		s.geoCache.error = ""
		s.geoCache.mu.Unlock()
		if old != nil {
			old.Close()
		}
		return
	}
	lease, err := statisticsGeoInstanceLease(false)
	if err != nil {
		return
	}
	defer lease.Close()
	store, err := s.statisticsGeoDataStore()
	if err != nil {
		s.setStatisticsGeoCacheError(instance, err.Error())
		return
	}
	store.verify = s.statisticsGeoStructureVerify
	s.refreshStatisticsGeoCacheStore(ctx, instance, store)
}

// Internal fixture seam, not a request/configurable path or key. Production
// calls only with the fixed root store and independent process verifier.
func (s *Service) refreshStatisticsGeoCacheStore(ctx context.Context, instance string, store statisticsGeoStore) {
	currentInstance, instanceErr := s.statisticsGeoInstance()
	if ctx == nil || ctx.Err() != nil || instanceErr != nil || currentInstance != instance {
		return
	}
	s.geoCache.mu.Lock()
	var retired *geodata.Snapshot
	if s.geoCache.instance != instance {
		retired = s.geoCache.snapshot
		s.geoCache.snapshot = nil
		s.geoCache.instance = instance
		s.geoCache.selected = ""
		s.geoCache.selectorRaw = nil
		s.geoCache.fallbackRaw = nil
		s.geoCache.error = ""
		s.geoCache.loadedAt = time.Time{}
	}
	s.geoCache.mu.Unlock()
	if retired != nil {
		retired.Close()
	}
	root, err := store.open(false)
	if errors.Is(err, os.ErrNotExist) {
		s.setStatisticsGeoCacheError(instance, "城市库目录不存在")
		return
	}
	if err != nil {
		s.setStatisticsGeoCacheError(instance, err.Error())
		return
	}
	defer root.Close()
	selected, raw, _, err := store.selector(root.Root)
	if err != nil {
		s.setStatisticsGeoCacheError(instance, err.Error())
		return
	}
	if selected.Dataset == "" {
		s.setStatisticsGeoCacheError(instance, "尚未选择已验签的城市库")
		return
	}
	s.geoCache.mu.RLock()
	unchanged := s.geoCache.instance == instance && s.geoCache.selected == selected.Dataset && bytes.Equal(raw, s.geoCache.selectorRaw) && s.geoCache.snapshot != nil && time.Since(s.geoCache.loadedAt) < 5*time.Minute
	hasSnapshot := s.geoCache.instance == instance && s.geoCache.snapshot != nil
	deferredFallback := !hasSnapshot && selected.Previous != "" && bytes.Equal(s.geoCache.fallbackRaw, raw)
	s.geoCache.mu.RUnlock()
	if unchanged {
		return
	}
	s.geoCache.mu.Lock()
	s.geoCache.instance = instance
	s.geoCache.loading = true
	s.geoCache.checkedAt = core.Now()
	s.geoCache.mu.Unlock()
	// Full structure verification uses the fixed bounded process in production.
	// Fall back only to this validated selector's explicit Previous reference;
	// never guess a retained directory, change the selector or lower high water.
	target := selected.Dataset
	warning := ""
	if deferredFallback {
		target = selected.Previous
	}
	a, snapshot, _, err := store.load(ctx, root.Root, target)
	if err != nil && target == selected.Dataset && !hasSnapshot && selected.Previous != "" && ctx.Err() == nil {
		currentError := err
		target = selected.Previous
		a, snapshot, _, err = store.load(ctx, root.Root, target)
		if err == nil {
			warning = "当前库核对失败，报表使用重新完整验签核对的旧库；磁盘选择未改变：" + currentError.Error()
		}
	}
	if err != nil {
		s.geoCache.mu.Lock()
		if !hasSnapshot && ctx.Err() != nil && target == selected.Dataset && selected.Previous != "" {
			s.geoCache.fallbackRaw = bytes.Clone(raw)
		} else {
			s.geoCache.fallbackRaw = nil
		}
		s.geoCache.mu.Unlock()
		s.setStatisticsGeoCacheError(instance, "城市库完整核对未通过："+err.Error())
		return
	}
	if target != selected.Dataset && warning == "" {
		warning = "当前库尚未核对完成，报表使用重新完整验签核对的旧库；磁盘选择未改变"
	}
	_, after, _, e := store.selector(root.Root)
	current, currentErr := s.statisticsGeoInstance()
	if e != nil || currentErr != nil || current != instance || !bytes.Equal(raw, after) || !root.current() {
		snapshot.Close()
		s.setStatisticsGeoCacheError(instance, "城市库或安装实例在校验期间变化，未替换内存副本")
		return
	}
	s.geoCache.mu.Lock()
	old := s.geoCache.snapshot
	s.geoCache.snapshot = snapshot
	s.geoCache.selected = target
	s.geoCache.appSHA = a.AppSHA256()
	s.geoCache.selectorRaw = bytes.Clone(raw)
	s.geoCache.fallbackRaw = nil
	s.geoCache.loading = false
	s.geoCache.error = warning
	s.geoCache.checkedAt = core.Now()
	s.geoCache.loadedAt = time.Now()
	s.geoCache.mu.Unlock()
	if old != nil {
		old.Close()
	}
}
func (s *Service) setStatisticsGeoCacheError(instance, message string) {
	s.geoCache.mu.Lock()
	defer s.geoCache.mu.Unlock()
	if s.geoCache.instance == instance && s.geoCache.snapshot != nil {
		message = fmt.Sprintf("%s；保留已完整核对的内存库 %s", message, s.geoCache.snapshot.Metadata(time.Now()).Release)
	} else {
		message += "；没有可用于报表的已验证内存库"
	}
	if len(message) > 1024 {
		message = message[:1024]
	}
	s.geoCache.instance = instance
	s.geoCache.loading = false
	s.geoCache.error = message
	s.geoCache.checkedAt = core.Now()
}
func (s *Service) runStatisticsGeoCacheWorker(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
		s.refreshStatisticsGeoCache(bounded)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Private records have a separate closed schema; no WAF-specific format
// decoder and no last-key-wins/case-alias behavior is reused here.
func decodeStatisticsGeoPrivate(raw []byte, out any) error {
	if len(raw) < 1 || len(raw) > 32<<10 {
		return errors.New("地域任务记录超限")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	allowed := map[string]bool{"format": true, "job_id": true, "selection": true, "envelope_sha256": true, "action": true, "app_version": true, "app_manifest_sha256": true, "installation_id": true, "release": true, "data_manifest_sha256": true, "state": true, "error": true, "steps": true, "time": true, "message": true}
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 6 || nodes > 256 {
			return errors.New("地域任务结构超限")
		}
		v, err := d.Token()
		if err != nil || v == nil {
			return errors.New("地域任务记录不完整或含null")
		}
		if delim, ok := v.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || !allowed[name] || seen[name] {
						return errors.New("地域任务字段重复、未知或非规范")
					}
					seen[name] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				if depth == 0 {
					return errors.New("地域任务须为对象")
				}
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("地域任务结构无效")
			}
			end, err := d.Token()
			if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
				return errors.New("地域任务结构不完整")
			}
		} else if depth == 0 {
			return errors.New("地域任务须为对象")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("地域任务含多余值")
	}
	return decodeFTPPrivateJSON(raw, out)
}
