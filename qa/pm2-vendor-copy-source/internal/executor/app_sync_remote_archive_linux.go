//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const remoteArchiveMaxJobs = 2048
const remoteArchiveMaxBytes int64 = 16 << 20

func (s *Service) remoteArchivePath(id string) string {
	return filepath.Join(s.remoteSyncDir(), "archive", id+".json")
}

func remotePrivateDirectory(p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	a, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm() != 0700 || !ok || a.Uid != uint32(os.Geteuid()) {
		return errors.New("远端任务私有目录身份或权限异常，未接管")
	}
	return nil
}

// Absence of a job in an unsafe/broken archive namespace is NOT a fresh ID.
func (s *Service) remoteArchiveDirectoryPresent() (bool, error) {
	p := filepath.Dir(s.remoteArchivePath(""))
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := remotePrivateDirectory(s.remoteSyncDir()); err != nil {
		return false, err
	}
	if err := remotePrivateDirectory(p); err != nil {
		return false, err
	}
	return true, nil
}

func remoteArchivableJob(j remoteSyncJob) bool {
	switch j.State {
	case "succeeded", "conflicts", "failed", "recovered":
	default:
		return false
	}
	created, e1 := time.Parse(time.RFC3339, j.CreatedAt)
	finished, e2 := time.Parse(time.RFC3339, j.FinishedAt)
	return e1 == nil && e2 == nil && !finished.Before(created)
}

func remoteJobSHA(j remoteSyncJob) string {
	// Exact private file bytes, including whitespace/unknown JSON fields. Only
	// a record read through the private no-follow reader has a valid digest.
	return j.RecordSHA
}

func (s *Service) allArchivedRemoteJobs() ([]remoteSyncJob, int64, error) {
	present, err := s.remoteArchiveDirectoryPresent()
	if err != nil {
		return nil, 0, err
	}
	if !present {
		return []remoteSyncJob{}, 0, nil
	}
	entries, err := os.ReadDir(filepath.Join(s.remoteSyncDir(), "archive"))
	if err != nil {
		return nil, 0, err
	}
	if len(entries) > remoteArchiveMaxJobs {
		return nil, 0, errors.New("归档超过 2048 份，未返回不完整库存")
	}
	var size int64
	jobs := make([]remoteSyncJob, 0, len(entries))
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !core.ValidID(id) {
			return nil, 0, errors.New("归档目录含未知记录，保留原记录")
		}
		st, e := os.Lstat(s.remoteArchivePath(id))
		if e != nil {
			return nil, 0, e
		}
		if st.Size() < 0 || st.Size() > 4<<20 || size > remoteArchiveMaxBytes-st.Size() {
			return nil, 0, errors.New("归档超过 16 MiB，未返回不完整库存")
		}
		size += st.Size()
		j, e := s.readRemoteJob(id)
		if e != nil || !j.Archived || !remoteArchivableJob(j) {
			return nil, 0, errors.New("归档任务身份或终态不可验证，保留原记录")
		}
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(i, k int) bool {
		return jobs[i].CreatedAt > jobs[k].CreatedAt || jobs[i].CreatedAt == jobs[k].CreatedAt && jobs[i].ID > jobs[k].ID
	})
	return jobs, size, nil
}

func (s *Service) remoteArchiveReport(in core.AppModuleInput) (any, error) {
	if in.Limit < 0 || in.Limit > 32 || in.Offset < 0 || in.Offset > remoteArchiveMaxJobs {
		return nil, errors.New("归档每页最多 32 条，起点最多 2048")
	}
	jobs, size, err := s.allArchivedRemoteJobs()
	if err != nil {
		return nil, err
	}
	limit := in.Limit
	if limit == 0 {
		limit = 16
	}
	start := min(in.Offset, len(jobs))
	end := min(start+limit, len(jobs))
	rows := []map[string]any{}
	for _, j := range jobs[start:end] {
		rows = append(rows, remotePublicJob(j, false))
	}
	return map[string]any{"remote_jobs": rows, "total": len(jobs), "archive_bytes": size, "limit": limit, "offset": in.Offset, "records_retained": true, "remote_files_changed": false, "scope": "本机完整任务记录的私有归档，最多 2048 份或 16 MiB；永久保留原任务身份，不删除远端备份、文件、检查点或取消记录。满额停止新归档，不自动清理证据。"}, nil
}

// Called under the executor mutex. Only one ordinary terminal record moves;
// the kernel performs an atomic no-overwrite rename on the same filesystem.
// Lookup checks both namespaces, so a lost reply or process exit cannot make
// the original task ID eligible for a new transfer.
func (s *Service) archiveRemoteJob(in core.AppModuleInput) (any, error) {
	j, err := s.readRemoteJob(in.RemoteRequestID)
	if err != nil {
		return nil, err
	}
	if !remoteArchivableJob(j) || !coreSHA.MatchString(in.ExpectedSHA) || in.ExpectedSHA != remoteJobSHA(j) || in.Confirm != "ARCHIVE REMOTE "+j.ID {
		return nil, errors.New("归档需要可验证终态、当前完整记录摘要和精确确认；执行中或中断记录保留")
	}
	if !j.Archived {
		cfg, e := s.readRemoteConfig(j.TargetID)
		if e != nil || cfg.SpecSHA != j.SpecSHA {
			return nil, errors.New("原连接身份不可验证，保留任务")
		}
		if e = remotePrivateFile(s.remoteCheckpointPath(j.TargetID)); e != nil {
			return nil, errors.New("原检查点缺失或不可验证，保留任务")
		}
		cp, e := s.readRemoteCheckpoint(cfg, j.SiteID)
		if e != nil || cp.Pending != nil {
			return nil, errors.New("原检查点损坏或仍有待恢复交接，保留任务")
		}
		archived, size, e := s.allArchivedRemoteJobs()
		if e != nil {
			return nil, e
		}
		st, e := os.Lstat(s.remoteJobPath(j.ID))
		if e != nil {
			return nil, e
		}
		if len(archived) >= remoteArchiveMaxJobs || st.Size() < 0 || size > remoteArchiveMaxBytes-st.Size() {
			return nil, errors.New("私有归档达到 2048 份或 16 MiB 上限，不自动删除证据")
		}
	}
	if err = remotePrivateDirectory(s.remoteSyncDir()); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(s.remoteSyncDir())
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = root.Mkdir("archive", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if _, err = s.remoteArchiveDirectoryPresent(); err != nil {
		return nil, err
	}
	openDir := func(name string) (*os.File, error) {
		if e := remotePrivateDirectory(filepath.Join(s.remoteSyncDir(), name)); e != nil {
			return nil, e
		}
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return nil, e
		}
		a, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || st.Mode().Perm() != 0700 || !ok || a.Uid != uint32(os.Geteuid()) {
			f.Close()
			return nil, errors.New("打开后的归档目录身份改变")
		}
		return f, nil
	}
	active, err := openDir("jobs")
	if err != nil {
		return nil, err
	}
	defer active.Close()
	archive, err := openDir("archive")
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	if !j.Archived {
		fresh, e := s.readRemoteJob(j.ID)
		if e != nil || fresh.Archived || remoteJobSHA(fresh) != in.ExpectedSHA {
			return nil, errors.New("所选记录改变，未归档")
		}
		file, e := root.OpenFile("jobs/"+j.ID+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return nil, e
		}
		e = file.Sync()
		file.Close()
		if e != nil {
			return nil, e
		}
		if e = unix.Renameat2(int(active.Fd()), j.ID+".json", int(archive.Fd()), j.ID+".json", unix.RENAME_NOREPLACE); e != nil {
			return nil, errors.New("归档目标已有记录或无法交接，未覆盖原证据")
		}
	}
	// Include the common parent: creating the archive directory must be durable.
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	for _, dir := range []*os.File{archive, active, parent} {
		if err = dir.Sync(); err != nil {
			return nil, errors.New("归档交接可能已完成但持久化无法确认；核对同一任务，不换标识重传")
		}
	}
	replayed := j.Archived
	j.Archived = true
	return map[string]any{"job": remotePublicJob(j, true), "archived": 1, "replayed": replayed, "records_retained": true, "remote_files_changed": false, "scope": "仅把所选已结束任务移动到本机私有归档；原任务仍可查询和重放，不执行远端同步，不删除备份、检查点或取消记录。"}, nil
}
