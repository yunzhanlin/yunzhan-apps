//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

type remoteSyncJob struct {
	Archived     bool     `json:"-"`
	RecordSHA    string   `json:"-"`
	ID           string   `json:"remote_request_id"`
	TargetID     string   `json:"remote_target_id"`
	PlanID       string   `json:"remote_plan_id,omitempty"`
	PlanRevision int64    `json:"remote_plan_revision,omitempty"`
	SiteID       string   `json:"site_id"`
	Revision     int64    `json:"revision"`
	SpecSHA      string   `json:"spec_sha256"`
	Excludes     []string `json:"excludes"`
	State        string   `json:"state"`
	CreatedAt    string   `json:"created_at"`
	StartedAt    string   `json:"started_at,omitempty"`
	FinishedAt   string   `json:"finished_at,omitempty"`
	Copied       int      `json:"copied_count"`
	Skipped      int      `json:"skipped_count"`
	Conflicts    []string `json:"conflicts"`
	Error        string   `json:"error,omitempty"`
}
type remoteSyncPending struct {
	ID    string      `json:"id"`
	JobID string      `json:"job_id"`
	Path  string      `json:"path"`
	New   moduleFile  `json:"new"`
	Old   *moduleFile `json:"old"`
}
type remoteSyncCheckpoint struct {
	TargetID string                `json:"target_id"`
	SiteID   string                `json:"site_id"`
	SpecSHA  string                `json:"spec_sha256"`
	Files    map[string]moduleFile `json:"files"`
	Pending  *remoteSyncPending    `json:"pending"`
}

func validRemoteFile(f moduleFile) bool {
	return coreSHA.MatchString(f.SHA) && f.Size >= 0 && f.Size <= 8<<20 && f.Mode <= 0777
}

var coreSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Service) remoteJobPath(id string) string {
	return filepath.Join(s.remoteSyncDir(), "jobs", id+".json")
}
func (s *Service) remoteCheckpointPath(id string) string {
	return filepath.Join(s.remoteSyncDir(), "checkpoints", id+".json")
}
func (s *Service) readRemoteCheckpoint(c remoteSyncConfig, site string) (remoteSyncCheckpoint, error) {
	var cp remoteSyncCheckpoint
	err := remoteRead(s.remoteCheckpointPath(c.ID), &cp)
	if errors.Is(err, os.ErrNotExist) {
		return remoteSyncCheckpoint{TargetID: c.ID, SiteID: site, SpecSHA: c.SpecSHA, Files: map[string]moduleFile{}}, nil
	}
	if err != nil {
		return cp, errors.New("远端同步检查点损坏，未覆盖目标")
	}
	if cp.TargetID != c.ID || cp.SpecSHA != c.SpecSHA || !core.ValidID(cp.SiteID) || site != "" && cp.SiteID != site || cp.Files == nil || len(cp.Files) > 10000 {
		return cp, errors.New("远端检查点与连接或源网站不匹配；每个远端连接仅接受一个源网站")
	}
	for name, f := range cp.Files {
		if !core.ValidFilePath(name, false) || !validRemoteFile(f) {
			return cp, errors.New("远端检查点包含无效文件记录")
		}
	}
	if p := cp.Pending; p != nil {
		if !core.ValidID(p.ID) || !core.ValidID(p.JobID) || !core.ValidFilePath(p.Path, false) || !validRemoteFile(p.New) || p.Old != nil && !validRemoteFile(*p.Old) {
			return cp, errors.New("远端待恢复事务无效")
		}
	}
	return cp, nil
}
func validateRemoteJob(j remoteSyncJob) error {
	if j.PlanID == "" && j.PlanRevision != 0 || j.PlanID != "" && (!syncPlanID.MatchString(j.PlanID) || j.PlanRevision < 1) {
		return errors.New("远端任务计划绑定无效")
	}
	if !core.ValidID(j.ID) || !syncPlanID.MatchString(j.TargetID) || !core.ValidID(j.SiteID) || j.Revision < 1 || !coreSHA.MatchString(j.SpecSHA) || len(j.Excludes) > 64 || j.Copied < 0 || j.Skipped < 0 || j.Copied+j.Skipped > 10000 || len(j.Conflicts) > 10000 {
		return errors.New("远端任务身份无效")
	}
	for _, p := range append(append([]string{}, j.Excludes...), j.Conflicts...) {
		if !core.ValidFilePath(p, false) {
			return errors.New("远端任务路径无效")
		}
	}
	if _, e := time.Parse(time.RFC3339, j.CreatedAt); e != nil {
		return errors.New("远端任务时间无效")
	}
	switch j.State {
	case "queued", "running", "succeeded", "conflicts", "failed", "interrupted", "recovered":
	default:
		return errors.New("远端任务状态无效")
	}
	return nil
}
func (s *Service) readRemoteJob(id string) (remoteSyncJob, error) {
	var j remoteSyncJob
	if !core.ValidID(id) {
		return j, errors.New("远端任务标识无效")
	}
	present, e := s.remoteArchiveDirectoryPresent()
	if e != nil {
		return j, e
	}
	archiveExists := false
	if present {
		_, e = os.Lstat(s.remoteArchivePath(id))
		archiveExists = e == nil
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return j, e
		}
	}
	jobPath := s.remoteJobPath(id)
	if archiveExists {
		if _, e = os.Lstat(jobPath); e == nil || !errors.Is(e, os.ErrNotExist) {
			return j, errors.New("任务身份在活动与归档命名空间重复或不可验证，未重新提交")
		}
		jobPath = s.remoteArchivePath(id)
	}
	if e := remoteRead(jobPath, &j); e != nil {
		return j, e
	}
	if j.ID != id {
		return j, errors.New("远端任务文件身份改变")
	}
	j.Archived = archiveExists
	if archiveExists && !remoteArchivableJob(j) {
		return j, errors.New("归档记录不是可验证终态，未重新提交")
	}
	return j, validateRemoteJob(j)
}
func (s *Service) allRemoteJobs() ([]remoteSyncJob, error) {
	entries, e := os.ReadDir(filepath.Join(s.remoteSyncDir(), "jobs"))
	if errors.Is(e, os.ErrNotExist) {
		return []remoteSyncJob{}, nil
	}
	if e != nil {
		return nil, e
	}
	if len(entries) > 128 {
		return nil, errors.New("远端任务超过 128 个上限，拒绝不完整结果")
	}
	jobs := []remoteSyncJob{}
	for _, v := range entries {
		if v.IsDir() || !strings.HasSuffix(v.Name(), ".json") {
			return nil, errors.New("远端任务目录含有未知记录")
		}
		j, e := s.readRemoteJob(strings.TrimSuffix(v.Name(), ".json"))
		if e != nil {
			return nil, e
		}
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(i, k int) bool {
		return jobs[i].CreatedAt < jobs[k].CreatedAt || jobs[i].CreatedAt == jobs[k].CreatedAt && jobs[i].ID < jobs[k].ID
	})
	return jobs, nil
}
func (s *Service) remoteTargetBusy(id string) (bool, error) {
	if pending, err := s.remoteBackupArchivePending(id); err != nil || pending {
		return pending, err
	}
	jobs, e := s.allRemoteJobs()
	if e != nil {
		return false, e
	}
	for _, j := range jobs {
		if j.TargetID == id && (j.State == "queued" || j.State == "running") {
			return true, nil
		}
	}
	var cp remoteSyncCheckpoint
	e = remoteRead(s.remoteCheckpointPath(id), &cp)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return cp.Pending != nil, nil
}

func (s *Service) remoteSyncUninstallPreflight() error {
	targets, err := os.ReadDir(filepath.Join(s.remoteSyncDir(), "targets"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(targets) > 16 {
		return errors.New("远端连接记录超限，未卸载")
	}
	for _, entry := range targets {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return errors.New("远端连接目录异常，未卸载")
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if pending, err := s.remoteBackupArchivePending(id); err != nil {
			return err
		} else if pending {
			return errors.New("远端备份归档待恢复，保留全部记录并拒绝卸载")
		}
	}
	plans, err := s.allRemotePlans()
	if err != nil {
		return err
	}
	for _, p := range plans {
		if p.Enabled {
			return errors.New("远端定时计划仍启用；请先暂停并核对原任务，计划和证据保留")
		}
	}
	jobs, e := s.allRemoteJobs()
	if e != nil {
		return e
	}
	for _, j := range jobs {
		if j.State == "queued" || j.State == "running" {
			return errors.New("远端同步仍在排队或执行；先请求取消并核对实际停止，再卸载，文件与凭据保留")
		}
	}
	entries, e := os.ReadDir(filepath.Join(s.remoteSyncDir(), "checkpoints"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if len(entries) > 16 {
		return errors.New("远端检查点数量异常，未卸载")
	}
	for _, v := range entries {
		if v.IsDir() || !strings.HasSuffix(v.Name(), ".json") {
			return errors.New("远端检查点目录异常，未卸载")
		}
		cfg, e := s.readRemoteConfig(strings.TrimSuffix(v.Name(), ".json"))
		if e != nil {
			return e
		}
		cp, e := s.readRemoteCheckpoint(cfg, "")
		if e != nil {
			return e
		}
		if cp.Pending != nil {
			return errors.New("存在远端文件交接待恢复事务；先核对并恢复，再卸载，全部备份保留")
		}
	}
	return nil
}
func (s *Service) queueRemoteSync(c remoteSyncConfig, in core.AppModuleInput) (any, error) {
	return s.queueRemotePlanSync(c, in, "", 0)
}
func (s *Service) queueRemotePlanSync(c remoteSyncConfig, in core.AppModuleInput, planID string, planRevision int64) (any, error) {
	if planID == "" && planRevision != 0 || planID != "" && (!syncPlanID.MatchString(planID) || planRevision < 1) {
		return nil, errors.New("远端任务内部计划绑定无效")
	}
	if in.Excludes == nil {
		in.Excludes = []string{}
	} else {
		in.Excludes = append([]string{}, in.Excludes...)
	}
	sort.Strings(in.Excludes)
	if !core.ValidID(in.RemoteRequestID) || !core.ValidID(in.SiteID) || len(in.Excludes) > 64 || in.TargetSiteID != "" || in.TargetProjectID != "" {
		return nil, errors.New("远端同步需要源网站和固定任务标识，不能同时填写本机目标")
	}
	for _, p := range in.Excludes {
		if !core.ValidFilePath(p, false) {
			return nil, errors.New("排除路径无效")
		}
	}
	if in.ExpectedRevision != c.Revision {
		return nil, errors.New("连接修订号改变，请重新选择远端连接")
	}
	old, e := s.readRemoteJob(in.RemoteRequestID)
	if e == nil {
		if old.TargetID != c.ID || old.SiteID != in.SiteID || old.Revision != c.Revision || old.SpecSHA != c.SpecSHA || old.PlanID != planID || old.PlanRevision != planRevision || !reflect.DeepEqual(old.Excludes, in.Excludes) {
			return nil, errors.New("该任务标识已绑定不同的同步请求")
		}
		return map[string]any{"job": remotePublicJob(old, true), "replayed": true}, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if !c.Enabled {
		return nil, errors.New("远端连接已停用")
	}
	if busy, e := s.remoteTargetBusy(c.ID); e != nil || busy {
		return nil, errors.New("该远端已有待执行或待恢复任务，不能重复排队")
	}
	jobs, e := s.allRemoteJobs()
	if e != nil {
		return nil, e
	}
	if len(jobs) >= 128 {
		return nil, errors.New("最多保留 128 个远端任务；不会自动删除事务证据")
	}
	f, e := s.openFiles(in.SiteID)
	if e != nil {
		return nil, e
	}
	f.Close()
	cp, e := s.readRemoteCheckpoint(c, in.SiteID)
	if e != nil {
		return nil, e
	}
	if cp.Pending != nil {
		return nil, errors.New("先恢复远端中断事务")
	}
	// Bind even an empty or entirely identical first transfer. Persist before
	// accepting a job; an interrupted queue write must never permit another
	// source to silently reuse this target's checkpoint namespace.
	if e = moduleWrite(s.remoteCheckpointPath(c.ID), cp); e != nil {
		return nil, e
	}
	j := remoteSyncJob{ID: in.RemoteRequestID, TargetID: c.ID, PlanID: planID, PlanRevision: planRevision, SiteID: in.SiteID, Revision: c.Revision, SpecSHA: c.SpecSHA, Excludes: in.Excludes, State: "queued", CreatedAt: core.Now(), Conflicts: []string{}}
	if e = moduleWrite(s.remoteJobPath(j.ID), j); e != nil {
		return nil, e
	}
	if j, e = s.readRemoteJob(j.ID); e != nil {
		return nil, e
	}
	return map[string]any{"job": remotePublicJob(j, true), "queued": true, "scope": remoteSyncScope}, nil
}
func (s *Service) remoteJobReport(in core.AppModuleInput) (any, error) {
	if in.RemoteRequestID != "" {
		j, e := s.readRemoteJob(in.RemoteRequestID)
		return map[string]any{"job": remotePublicJob(j, true), "scope": remoteSyncScope}, e
	}
	jobs, e := s.allRemoteJobs()
	if e != nil {
		return nil, e
	}
	if in.Limit < 0 || in.Limit > 32 || in.Offset < 0 || in.Offset > 128 {
		return nil, errors.New("远端任务分页每页最多 32 条，起点最多 128")
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
	return map[string]any{"remote_jobs": rows, "total": len(jobs), "limit": limit, "offset": in.Offset, "scope": remoteSyncScope}, nil
}

func remotePublicJob(j remoteSyncJob, details bool) map[string]any {
	paths := []string{}
	if details {
		paths = boundedModulePaths(j.Conflicts)
	}
	return map[string]any{"remote_request_id": j.ID, "remote_target_id": j.TargetID, "remote_plan_id": j.PlanID, "remote_plan_revision": j.PlanRevision, "site_id": j.SiteID, "revision": j.Revision, "state": j.State, "created_at": j.CreatedAt, "started_at": j.StartedAt, "finished_at": j.FinishedAt, "copied_count": j.Copied, "skipped_count": j.Skipped, "conflicts_count": len(j.Conflicts), "conflicts": paths, "report_limited": len(paths) < len(j.Conflicts), "error": j.Error, "job_archived": j.Archived, "job_sha256": remoteJobSHA(j)}
}
func (s *Service) remoteCancelPath(id string) string {
	return filepath.Join(s.remoteSyncDir(), "cancellations", id+".json")
}
func (s *Service) cancelRemoteSync(in core.AppModuleInput) (any, error) {
	j, e := s.readRemoteJob(in.RemoteRequestID)
	if e != nil {
		return nil, e
	}
	if j.State != "queued" && j.State != "running" {
		return map[string]any{"job": remotePublicJob(j, true), "cancel_requested": false}, nil
	}
	if e = moduleWrite(s.remoteCancelPath(j.ID), map[string]string{"job_id": j.ID, "requested_at": core.Now()}); e != nil {
		return nil, e
	}
	if j.State == "queued" {
		j.State = "failed"
		j.Error = "任务在执行前被取消，未传输文件"
		j.FinishedAt = core.Now()
		if e = moduleWrite(s.remoteJobPath(j.ID), j); e != nil {
			return nil, e
		}
		if j, e = s.readRemoteJob(j.ID); e != nil {
			return nil, e
		}
	}
	return map[string]any{"job": remotePublicJob(j, true), "cancel_requested": true, "scope": "停止后续文件交接；已完成文件、原文件备份及待恢复事务保留，不删除远端内容"}, nil
}

func remoteFileDigest(c *remoteSyncClient, p string) (moduleFile, bool, error) {
	st, e := c.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		return moduleFile{}, false, nil
	}
	if e != nil {
		return moduleFile{}, false, errors.New("远端文件不可读取")
	}
	if !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > 8<<20 || st.Mode()&os.ModeType != 0 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return moduleFile{}, false, errors.New("远端文件不是受限普通文件")
	}
	f, e := c.Open(p)
	if e != nil {
		return moduleFile{}, false, errors.New("远端文件无法打开")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if e != nil || int64(len(b)) != st.Size() {
		return moduleFile{}, false, errors.New("远端文件读取不完整")
	}
	after, e := c.Lstat(p)
	if e != nil || !after.Mode().IsRegular() || after.Size() != st.Size() || after.Mode() != st.Mode() || !after.ModTime().Equal(st.ModTime()) {
		return moduleFile{}, false, errors.New("远端文件在读取时改变")
	}
	return moduleFile{SHA: core.Hash(string(b)), Size: st.Size(), Mode: uint32(st.Mode().Perm())}, true, nil
}
func remoteParents(c *remoteSyncClient, cfg remoteSyncConfig, p string, owner uint32, create bool) error {
	if !core.ValidFilePath(p, false) {
		return errors.New("远端相对文件路径无效")
	}
	if _, e := remoteRoots(c, cfg); e != nil {
		return e
	}
	parent := path.Dir(p)
	if parent == "." {
		return nil
	}
	current := cfg.Target.Root
	for _, part := range strings.Split(parent, "/") {
		current = path.Join(current, part)
		st, e := c.Lstat(current)
		if errors.Is(e, os.ErrNotExist) && create {
			if e = c.Mkdir(current); e != nil {
				return errors.New("远端普通子目录创建失败")
			}
			if e = c.Chmod(current, 0755); e != nil {
				return e
			}
			if e = remoteSyncDirectory(c, current); e != nil {
				return e
			}
			if e = remoteSyncDirectory(c, path.Dir(current)); e != nil {
				return e
			}
			st, e = c.Lstat(current)
		}
		if errors.Is(e, os.ErrNotExist) && !create {
			return os.ErrNotExist
		}
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("远端子目录包含链接或不是普通目录")
		}
		attrs, ok := st.Sys().(*sftp.FileStat)
		if !ok || attrs.UID != owner || st.Mode().Perm()&0022 != 0 {
			return errors.New("远端子目录所有者改变或允许其他用户改写")
		}
	}
	return nil
}
func (s *Service) previewRemoteSync(ctx context.Context, c *remoteSyncClient, cfg remoteSyncConfig, in core.AppModuleInput) (any, error) {
	if len(in.Excludes) > 64 {
		return nil, errors.New("最多 64 个排除路径")
	}
	f, e := s.openFiles(in.SiteID)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	files, partial, e := scanModuleFiles(ctx, f.public, in.Excludes, nil)
	if e != nil || partial {
		return nil, errors.New("源目录扫描不完整，拒绝远端同步")
	}
	cp, e := s.readRemoteCheckpoint(cfg, in.SiteID)
	if e != nil {
		return nil, e
	}
	if cp.Pending != nil {
		return nil, errors.New("远端有中断文件交接，需要先恢复")
	}
	owner, e := remoteRoots(c, cfg)
	if e != nil {
		return nil, e
	}
	copies, conflicts := []string{}, []string{}
	for _, p := range sortedRemoteFiles(files) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		e = remoteParents(c, cfg, p, owner, false)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		current, exists, e := remoteFileDigest(c, path.Join(cfg.Target.Root, p))
		if e != nil {
			return nil, e
		}
		if exists && current == files[p] {
			continue
		}
		previous, tracked := cp.Files[p]
		if exists && (!tracked || previous != current) {
			conflicts = append(conflicts, p)
		} else {
			copies = append(copies, p)
		}
	}
	out := syncReport(true, copies, conflicts, filepath.Base(s.remoteCheckpointPath(cfg.ID)))
	out["scope"] = remoteSyncScope
	out["remote_target_id"] = cfg.ID
	out["revision"] = cfg.Revision
	return out, nil
}

func remoteNamespace(c *remoteSyncClient, cfg remoteSyncConfig, owner uint32) (string, error) {
	dir := path.Join(cfg.Target.BackupRoot, "yunzhan-sync-"+cfg.ID)
	st, e := c.Lstat(dir)
	if errors.Is(e, os.ErrNotExist) {
		if e = c.Mkdir(dir); e != nil {
			return "", errors.New("远端私有事务目录创建失败")
		}
		if e = c.Chmod(dir, 0700); e != nil {
			return "", e
		}
		if e = remoteSyncDirectory(c, dir); e != nil {
			return "", e
		}
		if e = remoteSyncDirectory(c, cfg.Target.BackupRoot); e != nil {
			return "", e
		}
		st, e = c.Lstat(dir)
	}
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return "", errors.New("远端私有事务目录不是 0700 普通目录")
	}
	a, ok := st.Sys().(*sftp.FileStat)
	if !ok || a.UID != owner {
		return "", errors.New("远端私有事务目录所有者改变")
	}
	entries, total, e := remoteBackupInventory(c, cfg, owner)
	if e != nil {
		return "", e
	}
	if len(entries) >= remoteBackupTransactions {
		return "", errors.New("远端事务达到 512 份上限，保留证据并暂停")
	}
	if total > remoteBackupBytes-remoteBackupReserve {
		return "", errors.New("远端备份预算不足，保留旧备份并暂停")
	}
	return dir, nil
}
func remoteTransactionPaths(cfg remoteSyncConfig, p remoteSyncPending) (string, string, string) {
	dir := path.Join(cfg.Target.BackupRoot, "yunzhan-sync-"+cfg.ID, p.ID)
	return dir, path.Join(dir, "staged"), path.Join(dir, "previous")
}

// OpenSSH OPEN with O_RDONLY produces a descriptor for Linux directories too;
// fsync@openssh.com flushes that descriptor. File fsync alone would not make the
// staged entry, old-file move or final publication durable across a power loss.
func remoteSyncDirectory(c *remoteSyncClient, p string) error {
	st, e := c.Lstat(p)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("远端刷盘目录身份无效")
	}
	f, e := c.Open(p)
	if e != nil {
		return errors.New("远端不能打开普通目录进行持久刷盘")
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !after.IsDir() {
		return errors.New("远端目录打开后身份改变")
	}
	if e = f.Sync(); e != nil {
		return errors.New("远端目录 fsync 未通过，不确认交接持久化")
	}
	return nil
}

// Publication uses hardlink@openssh.com, which refuses an existing destination.
// Never use PosixRename (overwrite) or truncate an existing destination. The old
// path is moved to a unique private location with ordinary SFTP v3 Rename; its
// contents are checked again after the move. A mismatch is preserved and blocks
// publication. Host-key pinning does not attest a malicious remote filesystem.
func (s *Service) commitRemoteFile(ctx context.Context, c *remoteSyncClient, cfg remoteSyncConfig, cp *remoteSyncCheckpoint, j remoteSyncJob, p string, data []byte, next moduleFile, old *moduleFile, owner uint32, guard func() error) error {
	if e := guard(); e != nil {
		return e
	}
	if e := remoteParents(c, cfg, p, owner, true); e != nil {
		return e
	}
	base, e := remoteNamespace(c, cfg, owner)
	if e != nil {
		return e
	}
	tx := remoteSyncPending{ID: core.ID(), JobID: j.ID, Path: p, New: next, Old: old}
	cp.Pending = &tx
	if e = moduleWrite(s.remoteCheckpointPath(cfg.ID), cp); e != nil {
		return e
	}
	dir, staged, previous := remoteTransactionPaths(cfg, tx)
	if path.Dir(dir) != base {
		return errors.New("远端事务路径无效")
	}
	if e = c.Mkdir(dir); e != nil {
		return errors.New("远端独立事务目录创建失败；请恢复检查点")
	}
	if e = c.Chmod(dir, 0700); e != nil {
		return e
	}
	if e = remoteSyncDirectory(c, base); e != nil {
		return e
	}
	f, e := c.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if e != nil {
		return errors.New("远端暂存文件不能无覆盖创建")
	}
	if e = f.Chmod(os.FileMode(next.Mode)); e == nil {
		_, e = io.Copy(f, bytes.NewReader(data))
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("远端暂存上传或持久刷盘失败；旧目标未主动覆盖")
	}
	if e = remoteSyncDirectory(c, dir); e != nil {
		return e
	}
	actual, exists, e := remoteFileDigest(c, staged)
	if e != nil || !exists || actual != next {
		return errors.New("远端暂存摘要不匹配，未交接目标")
	}
	if e = guard(); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e = remoteParents(c, cfg, p, owner, false); e != nil {
		return e
	}
	destination := path.Join(cfg.Target.Root, p)
	actual, exists, e = remoteFileDigest(c, destination)
	if e != nil || old == nil && exists || old != nil && (!exists || actual != *old) {
		return errors.New("远端目标在交接前改变，保留冲突与暂存文件")
	}
	if old != nil {
		if e = c.Rename(destination, previous); e != nil {
			return errors.New("远端原文件无法移入唯一私有备份")
		}
		if e = remoteSyncDirectory(c, dir); e != nil {
			return e
		}
		if e = remoteSyncDirectory(c, path.Dir(destination)); e != nil {
			return e
		}
		actual, exists, e = remoteFileDigest(c, previous)
		if e != nil || !exists || actual != *old {
			return errors.New("远端原文件在交接时改变，保留私有备份并停止，不发布新内容")
		}
	}
	if e = guard(); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e = c.Link(staged, destination); e != nil {
		return errors.New("远端无覆盖发布失败；保留原文件与暂存，请恢复事务")
	}
	if e = remoteSyncDirectory(c, path.Dir(destination)); e != nil {
		return e
	}
	actual, exists, e = remoteFileDigest(c, destination)
	if e != nil || !exists || actual != next {
		return errors.New("远端发布后的文件改变，保留证据并停止")
	}
	cp.Files[p] = next
	cp.Pending = nil
	if e = moduleWrite(s.remoteCheckpointPath(cfg.ID), cp); e != nil {
		return errors.New("远端文件已发布但检查点保存失败；需恢复，不会盲目重传")
	}
	return nil
}

func (s *Service) executeRemoteSync(ctx context.Context, cfg remoteSyncConfig, j *remoteSyncJob, guard func() error) error {
	if pending, err := s.remoteBackupArchivePending(cfg.ID); err != nil {
		return err
	} else if pending {
		return errors.New("备份归档待显式恢复，未执行新的文件交接")
	}
	f, e := s.openFiles(j.SiteID)
	if e != nil {
		return e
	}
	defer f.Close()
	files, partial, e := scanModuleFiles(ctx, f.public, j.Excludes, nil)
	if e != nil || partial {
		return errors.New("来源扫描不完整，未执行远端复制")
	}
	cp, e := s.readRemoteCheckpoint(cfg, j.SiteID)
	if e != nil {
		return e
	}
	if cp.Pending != nil {
		return errors.New("先恢复中断的远端文件事务")
	}
	conn, e := s.dialRemoteSync(ctx, cfg)
	if e != nil {
		return e
	}
	defer conn.Close()
	c := conn.client
	owner, e := remoteRoots(c, cfg)
	if e != nil {
		return e
	}
	for _, p := range sortedRemoteFiles(files) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e = guard(); e != nil {
			return e
		}
		e = remoteParents(c, cfg, p, owner, false)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		cur, exists, e := remoteFileDigest(c, path.Join(cfg.Target.Root, p))
		if e != nil {
			return e
		}
		next := files[p]
		if exists && cur == next {
			j.Skipped++
			continue
		}
		old, tracked := cp.Files[p]
		if exists && (!tracked || cur != old) {
			j.Conflicts = append(j.Conflicts, p)
			continue
		}
		data, e := readModuleFile(f.public, p)
		info, infoErr := f.public.Lstat(p)
		if e != nil || infoErr != nil || !info.Mode().IsRegular() || info.Size() != next.Size || uint32(info.Mode().Perm()) != next.Mode || core.Hash(string(data)) != next.SHA || int64(len(data)) != next.Size {
			return errors.New("来源文件在同步时改变；已完成文件检查点保留")
		}
		var expected *moduleFile
		if exists {
			expected = &cur
		}
		if e = s.commitRemoteFile(ctx, c, cfg, &cp, *j, p, data, next, expected, owner, guard); e != nil {
			return e
		}
		j.Copied++
		if e = moduleWrite(s.remoteJobPath(j.ID), j); e != nil {
			return errors.New("远端任务进度保存失败，已提交检查点保留")
		}
	}
	return nil
}

func (s *Service) recoverRemoteSync(ctx context.Context, cfg remoteSyncConfig) (any, error) {
	if pending, err := s.remoteBackupArchivePending(cfg.ID); err != nil {
		return nil, err
	} else if pending {
		return nil, errors.New("先核对并显式恢复原备份归档，不并发恢复文件交接")
	}
	cp, e := s.readRemoteCheckpoint(cfg, "")
	if e != nil {
		return nil, e
	}
	if cp.Pending == nil {
		return map[string]any{"recovered": false, "scope": "没有待恢复的文件交接；未执行同步"}, nil
	}
	p := *cp.Pending
	j, e := s.readRemoteJob(p.JobID)
	if e != nil {
		return nil, e
	}
	if j.State == "running" || j.State == "queued" {
		return nil, errors.New("任务仍在执行或排队，不能并发恢复")
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, e := s.dialRemoteSync(bounded, cfg)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	c := conn.client
	owner, e := remoteRoots(c, cfg)
	if e != nil {
		return nil, e
	}
	if e = remoteParents(c, cfg, p.Path, owner, false); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	dir, staged, previous := remoteTransactionPaths(cfg, p)
	if e = remoteDirCheck(c, path.Dir(dir), &owner, true); e != nil {
		return nil, errors.New("远端私有事务父目录不可验证，拒绝恢复")
	}
	if info, err := c.Lstat(dir); err == nil {
		a, ok := info.Sys().(*sftp.FileStat)
		if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || a.UID != owner {
			return nil, errors.New("远端事务目录改变，拒绝恢复")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("远端事务目录不可核对")
	}
	destination := path.Join(cfg.Target.Root, p.Path)
	current, exists, e := remoteFileDigest(c, destination)
	if e != nil {
		return nil, e
	}
	prior, hasPrior, e := remoteFileDigest(c, previous)
	if e != nil {
		return nil, e
	}
	stage, hasStage, e := remoteFileDigest(c, staged)
	if e != nil {
		return nil, e
	}
	if hasStage && stage != p.New {
		return nil, errors.New("暂存内容改变，保留证据并拒绝恢复")
	}
	if hasPrior && (p.Old == nil || prior != *p.Old) {
		return nil, errors.New("原文件备份改变，保留证据并拒绝自动恢复")
	}
	outcome := "unchanged"
	if exists && current == p.New && hasStage && (p.Old == nil || hasPrior) {
		cp.Files[p.Path] = p.New
		outcome = "committed"
	} else if p.Old != nil && hasPrior && !exists {
		if e = c.Link(previous, destination); e != nil {
			return nil, errors.New("原文件无覆盖恢复失败，可能出现新目标；保留备份")
		}
		if e = remoteSyncDirectory(c, path.Dir(destination)); e != nil {
			return nil, e
		}
		current, exists, e = remoteFileDigest(c, destination)
		if e != nil || !exists || current != *p.Old {
			return nil, errors.New("恢复后的原文件改变，未确认完成")
		}
		outcome = "rolled-back"
	} else if p.Old != nil && exists && current == *p.Old || p.Old == nil && !exists && !hasPrior {
		outcome = "unchanged"
	} else {
		return nil, errors.New("当前远端文件与可信事务不匹配；保留全部证据，拒绝覆盖")
	}
	cp.Pending = nil
	if e = moduleWrite(s.remoteCheckpointPath(cfg.ID), cp); e != nil {
		return nil, e
	}
	j.State = "recovered"
	j.FinishedAt = core.Now()
	j.Error = "中断文件交接已核对；剩余文件不会自动执行，重新预览并提交新任务"
	if e = moduleWrite(s.remoteJobPath(j.ID), j); e != nil {
		return nil, e
	}
	if j, e = s.readRemoteJob(j.ID); e != nil {
		return nil, e
	}
	return map[string]any{"job": remotePublicJob(j, true), "recovered": true, "outcome": outcome, "scope": "保留原文件、暂存与任务证据；不自动重试剩余同步"}, nil
}

func (s *Service) runRemoteSyncWorker(ctx context.Context) {
	s.mu.Lock()
	jobs, e := s.allRemoteJobs()
	if e == nil {
		for _, j := range jobs {
			if j.State == "running" {
				j.State = "interrupted"
				j.Error = "执行器重启，原任务安全暂停；核对检查点并显式恢复，不自动重新传输"
				j.FinishedAt = core.Now()
				_ = moduleWrite(s.remoteJobPath(j.ID), j)
			}
		}
	}
	s.mu.Unlock()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOneRemoteSyncJob(ctx)
		}
	}
}
func (s *Service) runOneRemoteSyncJob(ctx context.Context) {
	s.mu.Lock()
	if !s.moduleInstalled("files-sync") {
		s.mu.Unlock()
		return
	}
	s.scheduleRemotePlans(time.Now().UTC())
	jobs, e := s.allRemoteJobs()
	if e != nil {
		s.mu.Unlock()
		return
	}
	var selected *remoteSyncJob
	for i := range jobs {
		if jobs[i].State == "running" {
			s.mu.Unlock()
			return
		}
		if selected == nil && jobs[i].State == "queued" {
			selected = &jobs[i]
		}
	}
	if selected == nil {
		s.mu.Unlock()
		return
	}
	j := *selected
	cfg, e := s.readRemoteConfig(j.TargetID)
	if e == nil && (!cfg.Enabled || cfg.Revision != j.Revision || cfg.SpecSHA != j.SpecSHA) {
		e = errors.New("远端连接已停用或修订号改变，未执行任务")
	}
	if e == nil {
		e = s.remotePlanJobAllowed(j)
	}
	if e != nil {
		j.State = "failed"
		j.FinishedAt = core.Now()
		j.Error = "远端连接不可用或已改变，未执行任务"
		_ = moduleWrite(s.remoteJobPath(j.ID), j)
		s.mu.Unlock()
		return
	}
	j.State = "running"
	j.StartedAt = core.Now()
	if e = moduleWrite(s.remoteJobPath(j.ID), j); e != nil {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	guard := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		var cancellation map[string]string
		if e := remoteRead(s.remoteCancelPath(j.ID), &cancellation); e == nil || !errors.Is(e, os.ErrNotExist) {
			return errors.New("收到取消请求或取消记录不可验证，停止后续文件交接")
		}
		if !s.moduleInstalled("files-sync") {
			return errors.New("应用已卸载，停止后续远端交接")
		}
		if e := s.remotePlanJobAllowed(j); e != nil {
			return e
		}
		fresh, e := s.readRemoteConfig(cfg.ID)
		if e != nil || !fresh.Enabled || fresh.Revision != cfg.Revision || fresh.SpecSHA != cfg.SpecSHA {
			return errors.New("连接策略改变，停止后续远端交接")
		}
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 120*time.Second)
	e = s.executeRemoteSync(bounded, cfg, &j, guard)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	j.State = "succeeded"
	j.FinishedAt = core.Now()
	if len(j.Conflicts) > 0 {
		j.State = "conflicts"
	}
	if e != nil {
		j.State = "failed"
		j.Error = "同步未全部完成；已提交的检查点和原文件备份保留。" + safeRemoteSyncError(e)
	}
	if cp, err := s.readRemoteCheckpoint(cfg, j.SiteID); err != nil || cp.Pending != nil {
		j.State = "interrupted"
		j.Error = "有待核对的远端文件交接；不得盲目重传，请显式恢复。" + safeRemoteSyncError(e)
	}
	if err := moduleWrite(s.remoteJobPath(j.ID), j); err != nil {
		return
	}
	input := core.AppModuleInput{SiteID: j.SiteID, ResourceID: j.ID}
	if err := s.appendModuleEvent("files-sync", "queue-remote", "background", input, map[string]any{"copied_count": j.Copied, "conflicts_count": len(j.Conflicts)}, e); err != nil {
		j.State = "interrupted"
		j.Error = "文件可能已同步，但历史保存失败；任务暂停，检查记录后再提交"
		_ = moduleWrite(s.remoteJobPath(j.ID), j)
	}
}

// Transport/server errors are untrusted and can include peer-supplied secrets.
func safeRemoteSyncError(e error) string {
	if e == nil {
		return ""
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return "任务取消或超时"
	}
	return "连接、文件身份、冲突或持久化核验失败；请使用预览、连接检测或事务恢复定位，未执行不受限命令"
}
