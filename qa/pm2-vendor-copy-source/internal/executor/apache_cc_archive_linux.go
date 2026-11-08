//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

const apacheCCArchiveCount = 8
const apacheCCArchiveRetentionAttempts = 8
const apacheCCArchiveEntries = 5 + 2*apacheCCArchiveRetentionAttempts
const apacheCCArchiveFormat = 2

func apacheCCArchiveDirectoryEntries(path string, limit int) ([]os.DirEntry, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > limit {
		return nil, errors.New("CC 固定目录库存超过数量上限或无法完整读取")
	}
	return entries, nil
}

type apacheCCArchiveFile struct {
	Device uint64 `json:"device,string"`
	Inode  uint64 `json:"inode,string"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Every phase is a separate, exclusively created and durable file. A killed
// phase writer leaves its original bytes; a retry never replaces or completes
// an uncertain journal, exchanges names again, or truncates either inode.
type apacheCCArchiveIntent struct {
	Format         int                         `json:"format"`
	ID             string                      `json:"id"`
	At             string                      `json:"at"`
	Request        core.ApacheCCArchiveRequest `json:"request"`
	Source         apacheCCArchiveFile         `json:"source"`
	TailIncomplete bool                        `json:"tail_incomplete"`
}

type apacheCCArchivePrepared struct {
	Format  int                 `json:"format"`
	ID      string              `json:"id"`
	Fresh   apacheCCArchiveFile `json:"fresh"`
	Archive apacheCCArchiveFile `json:"archive"`
}

type apacheCCArchiveCompleted struct {
	Format  int                 `json:"format"`
	ID      string              `json:"id"`
	At      string              `json:"at"`
	Archive apacheCCArchiveFile `json:"archive"`
}

type apacheCCArchiveEntry struct {
	ID           string                    `json:"id"`
	State        string                    `json:"state"`
	Intent       *apacheCCArchiveIntent    `json:"intent,omitempty"`
	Prepared     *apacheCCArchivePrepared  `json:"prepared,omitempty"`
	Completed    *apacheCCArchiveCompleted `json:"completed,omitempty"`
	Retained     *apacheCCArchiveRetained  `json:"retained,omitempty"`
	RecordSHA    map[string]string         `json:"record_sha256"`
	Problem      string                    `json:"problem,omitempty"`
	SourceStatus string                    `json:"source_status,omitempty"`
}

func (s *Service) apacheCCArchiveDirectory() string {
	return s.systemPath("/var/lib/panel-apache-body/cc-archives")
}

func validApacheCCArchiveFile(v apacheCCArchiveFile) bool {
	return v.Device != 0 && v.Inode != 0 && v.Bytes >= 0 && v.Bytes <= apacheCCLogMaxBytes && wafLogDigestValid(v.SHA256)
}

func apacheCCArchiveStat(st os.FileInfo, uid, gid int) (apacheCCArchiveFile, error) {
	v := apacheCCArchiveFile{}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Size() < 0 || st.Size() > apacheCCLogMaxBytes || owner.Uid != uint32(uid) || owner.Gid != uint32(gid) || owner.Nlink != 1 {
		return v, errors.New("CC 日志文件身份、权限或容量不匹配，保留原文件")
	}
	v.Device, v.Inode, v.UID, v.GID, v.Bytes = uint64(owner.Dev), owner.Ino, owner.Uid, owner.Gid, st.Size()
	return v, nil
}

func apacheCCArchiveInspect(ctx context.Context, f *os.File, path string, uid, gid int) (apacheCCArchiveFile, error) {
	st, err := f.Stat()
	if err != nil {
		return apacheCCArchiveFile{}, err
	}
	v, err := apacheCCArchiveStat(st, uid, gid)
	if err != nil {
		return v, err
	}
	h := sha256.New()
	n, err := io.Copy(h, &contextReader{ctx, io.NewSectionReader(f, 0, apacheCCLogMaxBytes+1)})
	after, statErr := f.Stat()
	named, nameErr := os.Lstat(path)
	if err != nil || n != st.Size() || statErr != nil || nameErr != nil || !apacheBodyEventsSameFile(st, after) || !apacheBodyEventsSameFile(after, named) {
		return v, errors.New("CC 日志在核对期间变化，未采用部分内容")
	}
	v.SHA256 = hex.EncodeToString(h.Sum(nil))
	return v, nil
}

func (s *Service) apacheCCArchiveWorker() (int, int, error) {
	if s.Config.SystemRoot != "/" {
		return os.Geteuid(), os.Getegid(), nil // Private filesystem tests only.
	}
	return apacheBodyWorkerAccount()
}

func (s *Service) openApacheCCArchiveCurrent() (*os.File, error) {
	return s.openApacheCCArchiveCurrentMode(true)
}

func (s *Service) openApacheCCArchiveCurrentMode(writable bool) (*os.File, error) {
	parent := s.systemPath(apacheCCLogDirectory)
	if err := s.wafOwnedDirectory(parent, false); err != nil {
		return nil, err
	}
	st, err := os.Lstat(parent)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0755 {
		return nil, errors.New("CC 原日志父目录不可核对，未创建或接管")
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if writable {
		flags = os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	}
	f, err := os.OpenFile(s.systemPath(apacheCCLogPath), flags, 0)
	if err != nil {
		return nil, err
	}
	uid, gid, err := s.apacheCCArchiveWorker()
	if err == nil {
		_, err = apacheCCLogFileIdentity(f, uid, gid)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func apacheCCArchivePhase(dir, name string, value any) error {
	if name != "intent.json" && name != "prepared.json" && name != "completed.json" && !apacheCCArchiveRetentionFileName(name) {
		return errors.New("CC 归档记录阶段未实现")
	}
	b, err := json.MarshalIndent(value, "", "  ")
	limit := 4096
	if apacheCCArchiveRetentionFileName(name) {
		limit = 16384
	}
	if err != nil || len(b) >= limit {
		return errors.New("CC 归档记录超过固定容量")
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(append(b, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || n != len(b)+1 || syncErr != nil || closeErr != nil {
		return errors.New("CC 原记录写入未确认持久化；保留残件，不重复执行")
	}
	return apacheNumericLogSyncDirectory(dir)
}

func readApacheCCArchivePhase(path string, out any) (string, error) {
	return readApacheCCArchiveRecord(path, out, 4096)
}

func readApacheCCArchiveRecord(path string, out any, limit int64) (string, error) {
	if err := ownedRuntimePath(path, false); err != nil {
		return "", err
	}
	raw, err := apacheWAFReadStableFile(path, limit)
	if err != nil {
		return "", err
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return "", errors.New("CC 归档记录不是原私有单链接文件")
	}
	if validateWAFRotationJSONShape(raw) != nil || apacheBodyDecodeJSON(raw, out) != nil {
		return "", errors.New("CC 原记录不完整或含未知字段，未覆盖或补写")
	}
	return core.Hash(string(raw)), nil
}

// A pending directory is returned as unknown, including a zero-byte intent.
// It consumes capacity and prevents all new archive requests. Read-only UI and
// programme preflight never initialize, repair, chown or replay such evidence.
func (s *Service) readApacheCCArchive(ctx context.Context, id string) (apacheCCArchiveEntry, error) {
	out := apacheCCArchiveEntry{ID: id, State: "unknown", RecordSHA: map[string]string{}}
	if !core.ValidID(id) {
		return out, errors.New("CC 归档标识无效")
	}
	dir, _, err := s.apacheCCArchiveEntryDirectory(id)
	if err != nil {
		return out, err
	}
	entries, err := apacheCCArchiveDirectoryEntries(dir, apacheCCArchiveEntries)
	if err != nil {
		return out, errors.New("CC 原归档目录内容或数量异常")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if name != "intent.json" && name != "prepared.json" && name != "completed.json" && name != "data.log" && name != "next.log" && !apacheCCArchiveRetentionFileName(name) || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return out, errors.New("CC 原归档存在未知文件，未忽略或接管")
		}
		seen[name] = true
	}
	retained, digest, found, retentionErr := s.readApacheCCArchiveRetained(ctx, id, entries)
	if retentionErr != nil {
		return out, retentionErr
	}
	if found {
		out.State, out.Retained, out.RecordSHA["retained"], out.Problem = "retained-unknown", &retained, digest, "原结果未知；Root 独立副本与原始证据已保留，未重复归档"
		if _, ok := retained.Snapshot.Files["next.log"]; ok {
			out.SourceStatus = "not-authoritative"
		}
		return out, nil
	}
	for name := range seen {
		if apacheCCArchiveRetentionFileName(name) {
			if _, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil); err != nil {
				return out, err
			}
			out.Problem = "存在未完成的原证据保留记录，结果仍未知"
			return out, nil
		}
	}
	problem := func(message string) (apacheCCArchiveEntry, error) { out.Problem = message; return out, nil }
	var intent apacheCCArchiveIntent
	sha, err := readApacheCCArchivePhase(filepath.Join(dir, "intent.json"), &intent)
	if err != nil || intent.Format != apacheCCArchiveFormat || intent.ID != id || intent.Request.RequestID != id || intent.Request.ExpectedRevision < 1 || intent.Request.ExpectedRevision > 1000000000 || !validApacheNumericRotationTime(intent.At) || !validApacheCCArchiveFile(intent.Source) || intent.Source.Bytes == 0 || intent.TailIncomplete && !intent.Request.AllowIncomplete {
		return problem("原归档意图缺失或不完整，操作结果未知")
	}
	uid, gid, accountErr := s.apacheCCArchiveWorker()
	if accountErr != nil || intent.Source.UID != uint32(uid) || intent.Source.GID != uint32(gid) {
		return out, errors.New("CC 原日志意图不属于固定服务账户")
	}
	out.Intent, out.RecordSHA["intent"] = &intent, sha
	if !seen["prepared.json"] {
		return problem("原归档准备阶段未确认，不重复执行")
	}
	var prepared apacheCCArchivePrepared
	sha, err = readApacheCCArchivePhase(filepath.Join(dir, "prepared.json"), &prepared)
	if err != nil || prepared.Format != apacheCCArchiveFormat || prepared.ID != id || !validApacheCCArchiveFile(prepared.Fresh) || prepared.Fresh.Bytes != 0 || prepared.Fresh.SHA256 != core.Hash("") || prepared.Fresh.Device != intent.Source.Device || prepared.Fresh.Inode == intent.Source.Inode || prepared.Fresh.UID != intent.Source.UID || prepared.Fresh.GID != intent.Source.GID || !apacheCCIndependentCopy(prepared.Archive, intent.Source, prepared.Fresh) {
		return problem("原空日志准备记录无法核对，结果未知")
	}
	out.Prepared, out.RecordSHA["prepared"] = &prepared, sha
	if !seen["completed.json"] {
		return problem("原名称交换或封存结果未确认；原数据保留")
	}
	var completed apacheCCArchiveCompleted
	sha, err = readApacheCCArchivePhase(filepath.Join(dir, "completed.json"), &completed)
	if err != nil || completed.Format != apacheCCArchiveFormat || completed.ID != id || !validApacheNumericRotationTime(completed.At) || !validApacheCCArchiveFile(completed.Archive) {
		return problem("原完成回执不完整，未冒充成功")
	}
	if completed.Archive != prepared.Archive || completed.At < intent.At {
		return out, errors.New("CC 完成回执与原日志身份不一致")
	}
	f, err := os.OpenFile(filepath.Join(dir, "data.log"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	defer f.Close()
	actual, err := apacheCCArchivePrivateInspect(ctx, f, filepath.Join(dir, "data.log"))
	if err != nil || actual != completed.Archive {
		return out, errors.New("CC 原封存数据的内容或身份已变化，未显示为可用归档")
	}
	sourceWitness := intent.Source
	sourceWitness.UID, sourceWitness.GID = uint32(os.Geteuid()), completed.Archive.GID
	status, err := apacheCCArchiveSourceStatus(ctx, filepath.Join(dir, "next.log"), sourceWitness)
	if err != nil {
		return out, err
	}
	out.SourceStatus = status
	out.Completed, out.RecordSHA["completed"], out.State = &completed, sha, "completed"
	return out, nil
}

func (s *Service) apacheCCArchiveInventory(ctx context.Context) ([]apacheCCArchiveEntry, error) {
	return s.apacheCCArchiveInventoryAt(ctx, false)
}

func (s *Service) apacheCCArchiveHistoryInventory(ctx context.Context) ([]apacheCCArchiveEntry, error) {
	return s.apacheCCArchiveInventoryAt(ctx, true)
}

func (s *Service) apacheCCArchiveInventoryAt(ctx context.Context, history bool) ([]apacheCCArchiveEntry, error) {
	out := []apacheCCArchiveEntry{}
	dir, limit := s.apacheCCArchiveDirectory(), apacheCCArchiveCount
	if history {
		dir, limit = s.apacheCCArchiveHistoryDirectory(), apacheCCArchiveHistoryCount
	}
	if err := s.apacheNumericLogPrivateDirectory(dir, false); errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	entries, err := apacheCCArchiveDirectoryEntries(dir, limit)
	if err != nil {
		return nil, errors.New("CC 归档库存数量或目录异常，未执行新操作")
	}
	for _, file := range entries {
		if !file.IsDir() || !core.ValidID(file.Name()) {
			return nil, errors.New("CC 归档存在未知条目，未忽略原数据")
		}
		entry, err := s.readApacheCCArchive(ctx, file.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Filesystem primitive only. Public entrypoints must first verify the exact
// signed application, selected engine, live configuration and exclusive WAF
// lock. No caller path or callback is passed by production callers.
func (s *Service) archiveApacheCCLogAt(ctx context.Context, id string, checkpoint func(string) error) (apacheCCArchiveEntry, error) {
	// Internal filesystem fixture wrapper; HTTP supplies its complete original
	// typed request through archiveApacheCCLogRequestAt after all live gates.
	return s.archiveApacheCCLogRequestAt(ctx, core.ApacheCCArchiveRequest{RequestID: id, ExpectedRevision: 1, AllowIncomplete: true}, checkpoint)
}

func (s *Service) archiveApacheCCLogRequestAt(ctx context.Context, in core.ApacheCCArchiveRequest, checkpoint func(string) error) (apacheCCArchiveEntry, error) {
	id := in.RequestID
	out := apacheCCArchiveEntry{ID: id, State: "unknown", RecordSHA: map[string]string{}}
	if !core.ValidID(id) || in.ExpectedRevision < 1 || in.ExpectedRevision > 1000000000 {
		return out, errors.New("CC 原请求标识无效")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if _, _, err := s.readApacheCCArchiveClosed(id); err == nil {
		return out, errors.New("CC 原请求已明确关闭，拒绝迟到提交且未归档日志")
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return ctx.Err()
	}
	entries, err := s.apacheCCArchiveInventory(ctx)
	if err != nil {
		return out, err
	}
	history, err := s.apacheCCArchiveHistoryInventory(ctx)
	if err != nil {
		return out, err
	}
	all := append(append([]apacheCCArchiveEntry{}, entries...), history...)
	for _, entry := range all {
		if entry.ID == id {
			if entry.Intent == nil || entry.Intent.Request != in {
				return entry, errors.New("CC 原请求标识与原始参数不一致，未重复归档")
			}
			if entry.State != "completed" {
				return entry, errors.New("CC 原请求结果未知，仅允许核对；不会再次交换或清空日志")
			}
			return entry, nil
		}
	}
	if len(entries) >= apacheCCArchiveCount {
		return out, errors.New("CC 原归档已达 8 份，未删除历史或改变日志")
	}
	for _, entry := range all {
		if entry.State != "completed" && entry.State != "retained-unknown" {
			return out, errors.New("CC 原归档仍有未知结果，先核对原始证据")
		}
	}
	f, err := s.openApacheCCArchiveCurrent()
	if err != nil {
		return out, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return out, errors.New("CC 日志正在写入，本次未开始归档")
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	uid, gid, err := s.apacheCCArchiveWorker()
	if err != nil {
		return out, err
	}
	source, err := apacheCCArchiveInspect(ctx, f, s.systemPath(apacheCCLogPath), uid, gid)
	if err != nil || source.Bytes == 0 {
		return out, errors.New("CC 原日志为空或在核对期间变化，未归档")
	}
	var tail [1]byte
	if _, err := f.ReadAt(tail[:], source.Bytes-1); err != nil {
		return out, err
	}
	if tail[0] != '\n' && !in.AllowIncomplete {
		return out, errors.New("CC 原日志末行不完整；需明确选择保留全部原始末行后归档，未修改日志")
	}
	if err := s.apacheNumericLogPrivateDirectory(s.apacheCCArchiveDirectory(), true); err != nil {
		return out, err
	}
	dir := filepath.Join(s.apacheCCArchiveDirectory(), id)
	if err := os.Mkdir(dir, 0700); err != nil {
		return out, err
	}
	if err := apacheNumericLogSyncDirectory(s.apacheCCArchiveDirectory()); err != nil {
		return out, err
	}
	intent := apacheCCArchiveIntent{Format: apacheCCArchiveFormat, ID: id, At: core.Now(), Request: in, Source: source, TailIncomplete: tail[0] != '\n'}
	if err := apacheCCArchivePhase(dir, "intent.json", intent); err != nil {
		return out, err
	}
	if err := mark("intent-durable"); err != nil {
		return out, err
	}
	// This inode is created private to Root and is never exposed under a
	// worker-writable name or ownership. Existing producer descriptors refer
	// only to the original inode, not to this copy.
	copyPath := filepath.Join(dir, "data.log")
	copyFD, err := os.OpenFile(copyPath, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return out, err
	}
	defer copyFD.Close()
	if err := mark("copy-created"); err != nil {
		return out, err
	}
	if _, err := io.CopyBuffer(copyFD, &contextReader{ctx, io.NewSectionReader(f, 0, source.Bytes)}, make([]byte, 32<<10)); err != nil {
		return out, err
	}
	if err := copyFD.Sync(); err != nil {
		return out, err
	}
	copyIdentity, err := apacheCCArchivePrivateInspect(ctx, copyFD, copyPath)
	if err != nil || copyIdentity.Bytes != source.Bytes || copyIdentity.SHA256 != source.SHA256 || copyIdentity.Device != source.Device || copyIdentity.Inode == source.Inode {
		return out, errors.New("CC Root 独立副本未完整核对；保留残件，不交换原日志")
	}
	if err := apacheNumericLogSyncDirectory(dir); err != nil {
		return out, err
	}
	if err := mark("copy-durable"); err != nil {
		return out, err
	}
	stage := filepath.Join(dir, "next.log")
	fresh, err := os.OpenFile(stage, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return out, err
	}
	defer fresh.Close()
	if err := fresh.Chown(uid, gid); err != nil {
		return out, err
	}
	if err := unix.Flock(int(fresh.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return out, err
	}
	defer unix.Flock(int(fresh.Fd()), unix.LOCK_UN)
	if err := fresh.Sync(); err != nil {
		return out, err
	}
	identity, err := apacheCCArchiveInspect(ctx, fresh, stage, uid, gid)
	if err != nil || identity.Device != source.Device || identity.Inode == source.Inode {
		return out, errors.New("CC 新日志不是原文件系统上的独立私有空文件")
	}
	prepared := apacheCCArchivePrepared{apacheCCArchiveFormat, id, identity, copyIdentity}
	if err := apacheCCArchivePhase(dir, "prepared.json", prepared); err != nil {
		return out, err
	}
	if err := mark("prepared-durable"); err != nil {
		return out, err
	}
	parent, err := os.OpenFile(s.systemPath(apacheCCLogDirectory), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	defer parent.Close()
	archiveDir, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	defer archiveDir.Close()
	beforeExchange, err := apacheCCArchiveInspect(ctx, f, s.systemPath(apacheCCLogPath), uid, gid)
	freshBeforeExchange, freshErr := apacheCCArchiveInspect(ctx, fresh, stage, uid, gid)
	if err != nil || freshErr != nil || beforeExchange != source || freshBeforeExchange != identity {
		return out, errors.New("CC 原日志或准备文件已变化，未交换名称")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := unix.Renameat2(int(parent.Fd()), "cc-events.log", int(archiveDir.Fd()), "next.log", unix.RENAME_EXCHANGE); err != nil {
		return out, err // Never fall back to a non-atomic rename or copy/truncate.
	}
	if err := mark("names-exchanged"); err != nil {
		return out, err
	}
	// Preserve the original inode and retain the cooperative legacy writer's
	// ownership fence. This does not revoke a hostile open descriptor and is
	// never used as the independent copy's integrity authority.
	if err := f.Chown(os.Geteuid(), os.Getegid()); err != nil {
		return out, err
	}
	if err := f.Sync(); err != nil {
		return out, err
	}
	for _, fd := range []*os.File{parent, archiveDir} {
		if err := fd.Sync(); err != nil {
			return out, err
		}
	}
	sealed, err := apacheCCArchivePrivateInspect(ctx, copyFD, copyPath)
	active, activeErr := apacheCCArchiveInspect(ctx, fresh, s.systemPath(apacheCCLogPath), uid, gid)
	if err != nil || activeErr != nil || sealed != copyIdentity || active != identity {
		return out, errors.New("CC 名称交换后的原始数据或新日志无法核对，结果保持未知")
	}
	if err := mark("sealed-durable"); err != nil {
		return out, err
	}
	completed := apacheCCArchiveCompleted{apacheCCArchiveFormat, id, core.Now(), sealed}
	if err := apacheCCArchivePhase(dir, "completed.json", completed); err != nil {
		return out, err
	}
	if err := mark("completed-durable"); err != nil {
		return out, err
	}
	return s.readApacheCCArchive(ctx, id)
}

// No creation, repair, lock acquisition or phase completion during an upgrade.
func (s *Service) apacheCCArchiveReadFence(ctx context.Context) error {
	if _, err := s.apacheCCArchiveClosedInventory(ctx); err != nil {
		return err
	}
	entries, err := s.apacheCCArchiveInventory(ctx)
	if err != nil {
		return err
	}
	history, err := s.apacheCCArchiveHistoryInventory(ctx)
	if err != nil {
		return err
	}
	for _, entry := range append(entries, history...) {
		if entry.State != "completed" && entry.State != "retained-unknown" {
			return errors.New("CC 原日志归档结果仍未知，未跨越原操作升级")
		}
	}
	return ctx.Err()
}
