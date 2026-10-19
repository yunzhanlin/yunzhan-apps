//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

const statisticsGeoJobsArchiveRoot = "/var/lib/panel-executor/statistics-geodata-job-archive"

// Private test seam only. Production routes always use these two fixed paths;
// neither a caller, a dataset manifest nor a job payload can supply a path.
type statisticsGeoJobArchiveStore struct {
	active, archive string
	fault           func(string) error
}

func productionStatisticsGeoJobArchiveStore() statisticsGeoJobArchiveStore {
	return statisticsGeoJobArchiveStore{active: statisticsGeoJobsRoot, archive: statisticsGeoJobsArchiveRoot}
}
func (store statisticsGeoJobArchiveStore) checkpoint(point string) error {
	if store.fault != nil {
		return store.fault(point)
	}
	return nil
}
func statisticsGeoJobFileIdentities(root *os.Root) (map[string]os.FileInfo, error) {
	out := map[string]os.FileInfo{}
	for _, name := range []string{"request.json", "envelope.json", "started.json", "result.json", "install.lock"} {
		info, err := root.Lstat(name)
		if err != nil || !moduleRecordInfo(info, false, false) {
			return nil, errors.New("原终态文件身份异常")
		}
		out[name] = info
	}
	return out, nil
}
func statisticsGeoJobSameFiles(before, after map[string]os.FileInfo) bool {
	if len(before) != 5 || len(after) != 5 {
		return false
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			return false
		}
	}
	return true
}
func geoJobDirectory(path string, create bool) (*statisticsGeoDirectory, error) {
	return (statisticsGeoStore{base: path, trust: appcatalog.Default(), now: time.Now}).open(create)
}

func (store statisticsGeoJobArchiveStore) openJob(id string) (*statisticsGeoDirectory, *os.Root, bool, error) {
	if !core.ValidID(id) {
		return nil, nil, false, errors.New("地域任务标识无效")
	}
	var base *statisticsGeoDirectory
	var root *os.Root
	archived := false
	bad := func(err error) (*statisticsGeoDirectory, *os.Root, bool, error) {
		if root != nil {
			root.Close()
		}
		if base != nil {
			base.Close()
		}
		return nil, nil, false, err
	}
	for i, path := range []string{store.active, store.archive} {
		d, err := geoJobDirectory(path, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return bad(err)
		}
		info, err := d.Lstat(id)
		if errors.Is(err, os.ErrNotExist) {
			d.Close()
			continue
		}
		if err != nil || !moduleRecordInfo(info, true, false) {
			d.Close()
			return bad(errors.New("原地域任务目录身份异常"))
		}
		if root != nil {
			d.Close()
			return bad(errors.New("活动与归档中存在同一原任务；未覆盖任何证据"))
		}
		child, err := d.OpenRoot(id)
		if err != nil {
			d.Close()
			return bad(err)
		}
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(info, opened) || !d.current() {
			child.Close()
			d.Close()
			return bad(errors.New("地域原任务目录打开期间变化"))
		}
		base, root, archived = d, child, i == 1
	}
	if root == nil {
		return nil, nil, false, os.ErrNotExist
	}
	return base, root, archived, nil
}

// A terminal inventory is a hash of all five original files, not a hash of an
// unverified display row. Nonterminal requests remain visible but unarchivable.
func statisticsGeoJobRecord(root *os.Root, id string, archived bool) (core.StatisticsGeoJobRecord, error) {
	out := core.StatisticsGeoJobRecord{JobID: id, State: "pending", Archived: archived}
	if !core.ValidID(id) || statisticsGeoJobContents(root, true) != nil {
		return out, errors.New("地域原任务成员不能核对")
	}
	requestRaw, err := geoStoreRead(root, "request.json", 4096)
	var request statisticsGeoRequest
	if err != nil || decodeStatisticsGeoPrivate(requestRaw, &request) != nil || request.Format != 1 || request.JobID != id || core.ValidateStatisticsGeoSelection(request.Selection) != nil || !networkIDSRootSHA.MatchString(request.EnvelopeSHA) {
		return out, errors.New("原任务请求绑定损坏")
	}
	envelope, err := geoStoreRead(root, "envelope.json", appcatalog.MaxGeoDataEnvelopeBytes)
	if err != nil || core.Hash(string(envelope)) != request.EnvelopeSHA {
		return out, errors.New("原签名交付材料摘要损坏")
	}
	values := map[string][]byte{"request.json": requestRaw, "envelope.json": envelope}
	started, err := geoStoreRead(root, "started.json", 4096)
	if err == nil {
		var marker statisticsGeoRequest
		if decodeStatisticsGeoPrivate(started, &marker) != nil || marker != request {
			return out, errors.New("原启动回执不匹配")
		}
		values["started.json"] = started
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	resultRaw, err := geoStoreRead(root, "result.json", 32<<10)
	if err == nil {
		var result core.StatisticsGeoOperation
		if started == nil || decodeStatisticsGeoPrivate(resultRaw, &result) != nil || result.JobID != id || result.Selection != request.Selection || len(result.Steps) > 16 || len(result.Error) > 1024 || result.State != "succeeded" && result.State != "failed" || result.State == "succeeded" && result.Error != "" || result.State == "failed" && result.Error == "" {
			return out, errors.New("原终态回执绑定或结果损坏")
		}
		out.State = result.State
		values["result.json"] = resultRaw
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	lock, err := root.OpenFile("install.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err == nil {
		info, e := lock.Stat()
		visible, ve := root.Lstat("install.lock")
		lock.Close()
		if e != nil || ve != nil || !moduleRecordInfo(info, false, false) || info.Size() != 0 || !geoStoreStableInfo(info, visible) {
			return out, errors.New("原任务锁身份不能核对")
		}
		values["install.lock"] = []byte{}
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if out.State != "pending" && (values["started.json"] == nil || values["result.json"] == nil || values["install.lock"] == nil) {
		return out, errors.New("终态证据未完整保留")
	}
	if archived && out.State == "pending" {
		return out, errors.New("归档含非终态证据，未返回部分库存")
	}
	h := sha256.New()
	for _, name := range []string{"request.json", "envelope.json", "started.json", "result.json", "install.lock"} {
		if raw, ok := values[name]; ok {
			h.Write([]byte(name))
			h.Write([]byte{0})
			digest := sha256.Sum256(raw)
			h.Write(digest[:])
			out.Bytes += int64(len(raw))
		}
	}
	if out.State != "pending" {
		out.SHA = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}
func (store statisticsGeoJobArchiveStore) inventory() (core.StatisticsGeoJobInventory, error) {
	return store.inventoryContext(context.Background())
}
func (store statisticsGeoJobArchiveStore) inventoryContext(ctx context.Context) (core.StatisticsGeoJobInventory, error) {
	out := core.StatisticsGeoJobInventory{Entries: []core.StatisticsGeoJobRecord{}, ActiveMax: core.StatisticsGeoActiveJobsMax, ArchiveMax: core.StatisticsGeoArchivedJobsMax, ReadOnly: true}
	seen := map[string]bool{}
	for i, path := range []string{store.active, store.archive} {
		d, err := geoJobDirectory(path, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return out, err
		}
		dir, err := d.Open(".")
		if err != nil {
			d.Close()
			return out, err
		}
		max := out.ActiveMax
		if i == 1 {
			max = out.ArchiveMax
		}
		entries, err := dir.ReadDir(max + 1)
		dir.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(entries) > max {
			d.Close()
			return out, errors.New("原地域任务库存超过完整扫描上限；不自动清理")
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				d.Close()
				return out, err
			}
			id := entry.Name()
			info, e := d.Lstat(id)
			if !core.ValidID(id) || seen[id] || e != nil || !moduleRecordInfo(info, true, false) {
				d.Close()
				return out, errors.New("地域任务库存含未完成阶段、重复或不受信条目")
			}
			seen[id] = true
			root, e := d.OpenRoot(id)
			if e != nil {
				d.Close()
				return out, e
			}
			opened, e := root.Stat(".")
			if e != nil || !os.SameFile(info, opened) {
				root.Close()
				d.Close()
				return out, errors.New("原任务库存目录被替换")
			}
			row, e := statisticsGeoJobRecord(root, id, i == 1)
			root.Close()
			if e != nil {
				d.Close()
				return out, e
			}
			out.Entries = append(out.Entries, row)
		}
		if !d.current() {
			d.Close()
			return out, errors.New("地域任务库存基目录变化")
		}
		d.Close()
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].JobID < out.Entries[j].JobID })
	return out, nil
}

// No-overwrite, same-filesystem rename preserves all original bytes. A lost
// reply or Core crash is reconciled using the original ID and complete SHA.
// Nothing changes the dataset selector, high-water state, report or application.
func (store statisticsGeoJobArchiveStore) archiveJob(ctx context.Context, in core.StatisticsGeoArchiveInput) (core.StatisticsGeoArchiveResult, error) {
	var out core.StatisticsGeoArchiveResult
	if err := core.ValidateStatisticsGeoArchive(in); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	base, root, archived, err := store.openJob(in.JobID)
	if err != nil {
		return out, err
	}
	defer base.Close()
	defer root.Close()
	lock, err := root.OpenFile("install.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return out, errors.New("任务没有可核对的原启动锁，未归档")
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return out, errors.New("原任务仍持有执行锁，未归档")
	}
	lockInfo, err := lock.Stat()
	visible, verr := root.Lstat("install.lock")
	if err != nil || verr != nil || !moduleRecordInfo(lockInfo, false, false) || lockInfo.Size() != 0 || !geoStoreStableInfo(lockInfo, visible) {
		return out, errors.New("原任务锁被替换，未归档")
	}
	row, err := statisticsGeoJobRecord(root, in.JobID, archived)
	if err != nil || row.State == "pending" || row.SHA != in.SHA {
		return out, errors.New("原任务终态或完整摘要改变；未归档")
	}
	if archived {
		out.Record = row
		out.Replayed = true
		if err = ruleFeedStoreSync(base.Root); err != nil {
			return out, err
		}
		// Finish both sides of a rename whose original acknowledgement was lost.
		active, err := geoJobDirectory(store.active, false)
		if err != nil {
			return out, err
		}
		defer active.Close()
		return out, ruleFeedStoreSync(active.Root)
	}
	inventory, err := store.inventoryContext(ctx)
	if err != nil {
		return out, err
	}
	count := 0
	for _, r := range inventory.Entries {
		if r.Archived {
			count++
		}
	}
	if count >= core.StatisticsGeoArchivedJobsMax {
		return out, errors.New("私有归档区已满512份；原活动证据保留，未删除")
	}
	destination, err := geoJobDirectory(store.archive, true)
	if err != nil {
		return out, err
	}
	defer destination.Close()
	parent, err := os.OpenRoot(filepath.Dir(store.archive))
	if err != nil {
		return out, err
	}
	err = ruleFeedStoreSync(parent)
	parent.Close()
	if err != nil {
		return out, err
	}
	identities, err := statisticsGeoJobFileIdentities(root)
	if err != nil {
		return out, err
	}
	// Recheck the complete selected record just before the atomic handoff.
	after, err := statisticsGeoJobRecord(root, in.JobID, false)
	info, e := base.Lstat(in.JobID)
	opened, oe := root.Stat(".")
	if err != nil || after != row || e != nil || oe != nil || !os.SameFile(info, opened) || !base.current() || !destination.current() || ctx.Err() != nil {
		return out, errors.New("原证据交接前变化，未归档")
	}
	for _, name := range []string{"request.json", "envelope.json", "started.json", "result.json", "install.lock"} {
		f, e := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return out, e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return out, e
		}
	}
	if err = ruleFeedStoreSync(root); err != nil {
		return out, err
	}
	if err = store.checkpoint("before-rename"); err != nil {
		return out, err
	}
	currentFiles, err := statisticsGeoJobFileIdentities(root)
	finalRow, rowErr := statisticsGeoJobRecord(root, in.JobID, false)
	if err != nil || rowErr != nil || !statisticsGeoJobSameFiles(identities, currentFiles) || finalRow != row || !base.current() || !destination.current() {
		return out, errors.New("原文件交接前身份或字节改变，未归档")
	}
	src, err := base.Open(".")
	if err != nil {
		return out, err
	}
	defer src.Close()
	dst, err := destination.Open(".")
	if err != nil {
		return out, err
	}
	defer dst.Close()
	if err = unix.Renameat2(int(src.Fd()), in.JobID, int(dst.Fd()), in.JobID, unix.RENAME_NOREPLACE); err != nil {
		return out, err
	}
	if err = store.checkpoint("after-rename"); err != nil {
		return out, err
	}
	if src.Sync() != nil || dst.Sync() != nil {
		return out, errors.New("原证据已交接但持久性未核对；使用同一标识和摘要核对，不重新生成")
	}
	if err = store.checkpoint("after-sync"); err != nil {
		return out, err
	}
	newInfo, e := destination.Lstat(in.JobID)
	if e != nil || !os.SameFile(info, newInfo) || !base.current() || !destination.current() {
		return out, errors.New("归档交接后的身份不能核对")
	}
	verified, err := statisticsGeoJobRecord(root, in.JobID, true)
	finalFiles, filesErr := statisticsGeoJobFileIdentities(root)
	if err != nil || filesErr != nil || !statisticsGeoJobSameFiles(identities, finalFiles) || verified.SHA != in.SHA || verified.State != row.State || verified.Bytes != row.Bytes {
		return out, errors.New("原归档内容交接后不能完整核对")
	}
	out.Record = verified
	return out, nil
}
func (s *Service) statisticsGeoArchiveRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/statistics/geodata-job-records/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "原证据导出不接受查询字段"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 512))
		in, de := core.DecodeStatisticsGeoExport(raw)
		if err != nil || de != nil {
			respond(w, 400, map[string]string{"error": "原证据导出绑定无效"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err = upgradeguard.CheckStartup(); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		out, err := productionStatisticsGeoJobArchiveStore().exportJobWithInstanceLease(r.Context(), in, statisticsGeoInstanceLock)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/statistics/geodata-job-records", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "原库存不接受查询字段"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		out, err := productionStatisticsGeoJobArchiveStore().inventoryContext(r.Context())
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/statistics/geodata-job-records/archive", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "原归档不接受查询字段"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		in, de := core.DecodeStatisticsGeoArchive(raw)
		if err != nil || de != nil {
			respond(w, 400, map[string]string{"error": "原归档绑定字段无效"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err = upgradeguard.CheckStartup(); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		lease, err := statisticsGeoInstanceLease(true)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		defer lease.Close()
		out, err := productionStatisticsGeoJobArchiveStore().archiveJob(r.Context(), in)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}

// Keep original worker/status/replay IDs readable after archival. Never return
// a newly generated request or accept a duplicate active/archived directory.
func readStatisticsGeoJobAt(store statisticsGeoJobArchiveStore, id string) (statisticsGeoRequest, []byte, *statisticsGeoDirectory, *os.Root, error) {
	var request statisticsGeoRequest
	base, root, _, err := store.openJob(id)
	if err != nil {
		return request, nil, nil, nil, err
	}
	bad := func(err error) (statisticsGeoRequest, []byte, *statisticsGeoDirectory, *os.Root, error) {
		root.Close()
		base.Close()
		return request, nil, nil, nil, err
	}
	if err = statisticsGeoJobContents(root, true); err != nil {
		return bad(err)
	}
	raw, err := geoStoreRead(root, "request.json", 4096)
	if err != nil || decodeStatisticsGeoPrivate(raw, &request) != nil || request.Format != 1 || request.JobID != id || core.ValidateStatisticsGeoSelection(request.Selection) != nil || !networkIDSRootSHA.MatchString(request.EnvelopeSHA) {
		return bad(errors.New("地域任务原始请求损坏"))
	}
	envelope, err := geoStoreRead(root, "envelope.json", appcatalog.MaxGeoDataEnvelopeBytes)
	if err != nil || core.Hash(string(envelope)) != request.EnvelopeSHA {
		return bad(errors.New("地域任务原始签名材料损坏"))
	}
	return request, bytes.Clone(envelope), base, root, nil
}
