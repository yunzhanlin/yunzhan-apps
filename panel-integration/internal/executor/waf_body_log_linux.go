//go:build linux

package executor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const wafBodyLogPath = "/var/lib/panel-waf/body-events.log"
const wafBodyLegacyLogPath = "/var/log/nginx/panel-waf-body-events.log"
const wafBodyLogLimit int64 = 32 << 20
const wafBodyLogArchiveLimit = 8

// Nginx's normal USR1 reopen changes a log's owner to its worker account.
// Trust only that fixed account inside a root-owned, non-writable directory;
// website/PHP accounts cannot traverse it or read its numerical metadata.
func (s *Service) wafBodyLogAccount() (int, int, error) {
	if s.Config.SystemRoot != "/" {
		return os.Geteuid(), os.Getegid(), nil // Explicit isolated filesystem fixtures.
	}
	account, err := user.Lookup("www-data")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1 {
		return 0, 0, errors.New("Nginx 日志账户无效")
	}
	gid, err := strconv.Atoi(account.Gid)
	return uid, gid, err
}

func (s *Service) prepareWAFBodyLog() error {
	_, gid, err := s.wafBodyLogAccount()
	if err != nil {
		return err
	}
	path := s.systemPath(wafBodyLogPath)
	directory := filepath.Dir(path)
	_, beforeErr := os.Lstat(directory)
	created := errors.Is(beforeErr, os.ErrNotExist)
	if beforeErr != nil && !created {
		return beforeErr
	}
	if err := s.wafOwnedDirectory(directory, true); err != nil {
		return err
	}
	st, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if st.Mode().Perm() != 0750 || st.Sys().(*syscall.Stat_t).Gid != uint32(gid) {
		if !created {
			return errors.New("已有请求体日志目录权限或组不匹配，未接管")
		}
		// Newly provisioned directory is fixed-owned; never take a writable or
		// foreign ancestor. Existing active files must pass their own contract.
		if err := os.Chown(directory, os.Geteuid(), gid); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0750); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = s.openWAFBodyLog(false, false)
		if err == nil {
			err = f.Close()
		}
		return err
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chown(os.Geteuid(), gid); err != nil {
		return err
	}
	if err := f.Chmod(0640); err != nil {
		return err
	}
	return f.Sync()
}

func (s *Service) openWAFBodyLog(writable, legacy bool) (*os.File, error) {
	path := s.systemPath(wafBodyLogPath)
	if legacy {
		path = s.systemPath(wafBodyLegacyLogPath)
	}
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	if !legacy {
		st, err := os.Lstat(filepath.Dir(path))
		_, gid, accountErr := s.wafBodyLogAccount()
		if err != nil || accountErr != nil || st.Mode().Perm() != 0750 || st.Sys().(*syscall.Stat_t).Gid != uint32(gid) {
			return nil, errors.New("请求体日志目录权限或组异常")
		}
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if writable {
		flags = os.O_RDWR | syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	uid, gid, err := s.wafBodyLogAccount()
	ownerOK := ok && (stat.Uid == uint32(os.Geteuid()) || !legacy && stat.Uid == uint32(uid))
	modeOK := st.Mode().Perm() == 0640 && ok && stat.Gid == uint32(gid)
	if legacy {
		modeOK = st.Mode().Perm()&0022 == 0
	}
	if err != nil || !st.Mode().IsRegular() || !ownerOK || !modeOK || stat.Nlink != 1 || st.Size() < 0 || !legacy && st.Size() > wafBodyLogLimit {
		f.Close()
		return nil, errors.New("请求体元数据日志归属、权限、大小或链接数异常")
	}
	return f, nil
}

// This is an absence check, never an authorization to read a legacy file.
// Ubuntu's root-owned /var/log may be group-writable by syslog. Missing legacy
// metadata there must not break a panel that never enabled the body engine.
// Existing files still pass the original strict open/owner/permission checks;
// links, foreign ancestors and world-writable paths never look like absence.
func (s *Service) wafLegacyBodyLogMissing() (bool, error) {
	anchor := s.Config.SystemRoot
	if !filepath.IsAbs(anchor) || filepath.Clean(anchor) != anchor {
		return false, errors.New("日志观察根路径无效")
	}
	if err := ownedRuntimePath(anchor, true); err != nil {
		return false, err
	}
	parts := []string{"var", "log", "nginx", "panel-waf-body-events.log"}
	path := anchor
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("历史日志观察路径为链接，未当成缺失日志")
		}
		if i == len(parts)-1 {
			return false, nil // Existing data must pass openWAFBodyLog unchanged.
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		writable := info.Mode().Perm()&0022 != 0
		if i == 1 { // Only the fixed /var/log absence lookup allows group write.
			writable = info.Mode().Perm()&0002 != 0
		}
		if !info.IsDir() || !ok || stat.Uid != uint32(os.Geteuid()) || writable {
			return false, errors.New("历史日志观察祖先归属或权限异常，未当成缺失日志")
		}
	}
	return false, nil
}

type wafBodyLogArchive struct {
	ID         string `json:"id"`
	CapturedAt string `json:"captured_at"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	State      string `json:"state"`
}

func (s *Service) wafBodyLogArchiveDirectory() string {
	return s.systemPath("/var/lib/panel-waf/archives")
}

func wafLogDigestValid(sha string) bool {
	return len(sha) == 64 && strings.Trim(sha, "0123456789abcdef") == ""
}

// Reading an index is deliberately independent of the copy. A durable intent
// precedes creation of that copy, so power loss can leave a known missing or
// partial snapshot without making an unowned orphan look like panel history.
func (s *Service) readWAFBodyLogIndex(id string) (wafBodyLogArchive, string, error) {
	var entry wafBodyLogArchive
	if !core.ValidID(id) {
		return entry, "", errors.New("元数据备份标识无效")
	}
	index := filepath.Join(s.wafBodyLogArchiveDirectory(), id+".json")
	if err := ownedRuntimePath(index, false); err != nil {
		return entry, "", err
	}
	f, err := os.OpenFile(index, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return entry, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1024 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		return entry, "", errors.New("元数据备份索引权限或大小异常")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		return entry, "", err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		return entry, "", errors.New("元数据备份索引不可解析")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return entry, "", errors.New("元数据备份索引存在额外内容")
	}
	states := map[string]bool{"copying": true, "prepared": true, "completed": true, "retained": true, "retained-incomplete": true, "retained-missing": true, "removing": true}
	if entry.ID != id || entry.Bytes < 0 || entry.Bytes > wafBodyLogLimit || !wafLogDigestValid(entry.SHA256) || !states[entry.State] || entry.Bytes == 0 && entry.State != "retained-incomplete" && entry.State != "removing" {
		return entry, "", errors.New("元数据备份索引无效")
	}
	if _, err := time.Parse(time.RFC3339, entry.CapturedAt); err != nil {
		return entry, "", errors.New("元数据备份时间无效")
	}
	hash := sha256.Sum256(data)
	return entry, hex.EncodeToString(hash[:]), nil
}

type wafBodyLogRecovery struct {
	Archive         wafBodyLogArchive `json:"archive"`
	IndexSHA        string            `json:"index_sha256"`
	SnapshotSHA     string            `json:"snapshot_sha256"`
	SnapshotBytes   int64             `json:"snapshot_bytes"`
	SnapshotMissing bool              `json:"snapshot_missing"`
}

func (s *Service) wafBodyLogRecoveryEntries(ctx context.Context) ([]wafBodyLogRecovery, error) {
	out := []wafBodyLogRecovery{}
	dir := s.wafBodyLogArchiveDirectory()
	if err := s.wafOwnedDirectory(dir, false); errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil || st.Mode().Perm() != 0700 {
		return nil, errors.New("元数据备份目录权限异常")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) > wafBodyLogArchiveLimit*2 {
		return nil, errors.New("元数据备份数量或目录异常")
	}
	ids := map[string]bool{}
	for _, file := range files {
		id, suffix, ok := strings.Cut(file.Name(), ".")
		if !ok || !core.ValidID(id) || (suffix != "log" && suffix != "json") || file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("备份目录存在未知文件，未自动接管")
		}
		ids[id] = true
	}
	if len(ids) > wafBodyLogArchiveLimit {
		return nil, errors.New("元数据快照标识超过固定数量上限")
	}
	for id := range ids {
		entry, indexSHA, err := s.readWAFBodyLogIndex(id)
		if err != nil {
			return nil, err
		}
		pending := entry.State == "copying" || entry.State == "prepared" || entry.State == "removing"
		item := wafBodyLogRecovery{Archive: entry, IndexSHA: indexSHA}
		f, err := s.openWAFBodyLogArchive(id)
		if errors.Is(err, os.ErrNotExist) {
			if !pending && entry.State != "retained-missing" {
				return nil, errors.New("已完成或保留的快照缺失，未用其它恢复记录掩盖异常")
			}
			item.SnapshotMissing = true
		} else if err != nil {
			return nil, err
		} else {
			st, err := f.Stat()
			f.Close()
			if err != nil {
				return nil, err
			}
			item.SnapshotBytes = st.Size()
			item.SnapshotSHA, err = wafNativeFileSHA(ctx, filepath.Join(dir, id+".log"), wafBodyLogLimit)
			if err != nil {
				return nil, err
			}
		}
		if !pending {
			if entry.State == "retained-missing" && !item.SnapshotMissing || entry.State != "retained-missing" && (item.SnapshotSHA != entry.SHA256 || item.SnapshotBytes != entry.Bytes) {
				return nil, errors.New("已完成或保留的快照摘要、大小或缺失状态变化，未接管")
			}
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Archive.ID < out[j].Archive.ID })
	return out, nil
}

// Retain evidence, do not finish an uncertain truncate or fabricate success.
// Explicit digest-bound recovery never writes/truncates the current log.
func (s *Service) retainWAFBodyLogSnapshot(ctx context.Context, selected wafBodyLogRecovery) error {
	if !core.ValidID(selected.Archive.ID) || !wafLogDigestValid(selected.IndexSHA) || (!selected.SnapshotMissing && !wafLogDigestValid(selected.SnapshotSHA)) || selected.SnapshotMissing && selected.SnapshotSHA != "" {
		return errors.New("恢复记录身份或摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	entries, err := s.wafBodyLogRecoveryEntries(ctx)
	if err != nil {
		return err
	}
	for _, current := range entries {
		if current.Archive.ID != selected.Archive.ID {
			continue
		}
		if current.IndexSHA != selected.IndexSHA || current.SnapshotSHA != selected.SnapshotSHA || current.SnapshotMissing != selected.SnapshotMissing {
			return errors.New("恢复记录已变化，未接管或修改")
		}
		if current.Archive.State == "removing" {
			return errors.New("所选快照处于明确删除事务，请以原摘要重试删除；不会当作完整备份")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Preserve the original intent and the observed copy before repairing
		// its index. A fixed quota prevents repeated failures from growing an
		// unbounded recovery history. No failed evidence is silently removed.
		directory := filepath.Join(s.Config.SecurityDir, "waf-log-recovery")
		if err := s.wafBodyLogPrivateDirectory(directory, true); err != nil {
			return err
		}
		files, err := os.ReadDir(directory)
		if err != nil || len(files) >= 100 {
			return errors.New("日志恢复证据已达 100 份，请先人工归档；原日志未动")
		}
		if err := moduleWrite(filepath.Join(directory, core.ID()+".json"), map[string]any{"created_at": core.Now(), "observed": current, "current_log_untouched": true, "rotation_outcome": "unknown_not_marked_successful"}); err != nil {
			return err
		}
		next := current.Archive
		if current.SnapshotMissing {
			next.State = "retained-missing"
		} else {
			next.State = "retained"
			if current.SnapshotSHA != next.SHA256 || current.SnapshotBytes != next.Bytes {
				next.State = "retained-incomplete"
			}
			next.Bytes = current.SnapshotBytes
			next.SHA256 = current.SnapshotSHA
		}
		return s.writeWAFBodyLogIndex(ctx, next)
	}
	return errors.New("所选快照没有可核对的未完成恢复记录")
}

func (s *Service) wafBodyLogArchives() ([]wafBodyLogArchive, error) {
	entries := []wafBodyLogArchive{}
	directory := s.wafBodyLogArchiveDirectory()
	if err := s.wafOwnedDirectory(directory, false); errors.Is(err, os.ErrNotExist) {
		return entries, nil
	} else if err != nil {
		return nil, err
	}
	st, err := os.Lstat(directory)
	if err != nil || st.Mode().Perm() != 0700 {
		return nil, errors.New("元数据备份目录权限异常")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) > wafBodyLogArchiveLimit*2 {
		return nil, errors.New("元数据备份目录不可读取或数量超限")
	}
	ids := map[string]bool{}
	for _, file := range files {
		name := file.Name()
		id, suffix, ok := strings.Cut(name, ".")
		if !ok || !core.ValidID(id) || (suffix != "log" && suffix != "json") || file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("元数据备份目录存在未知条目，未接管")
		}
		ids[id] = true
	}
	if len(ids) > wafBodyLogArchiveLimit {
		return nil, errors.New("元数据快照标识超过固定数量上限")
	}
	for id := range ids {
		entry, _, err := s.readWAFBodyLogIndex(id)
		if err != nil {
			return nil, err
		}
		if entry.State == "copying" || entry.State == "removing" {
			return nil, errors.New("存在未完成日志复制或删除事务，请先核对恢复记录；当前日志未修改")
		}
		f, err := s.openWAFBodyLogArchive(id)
		if entry.State == "retained-missing" && errors.Is(err, os.ErrNotExist) {
			entries = append(entries, entry)
			continue
		}
		if entry.State == "retained-missing" && err == nil {
			f.Close()
			return nil, errors.New("已标记缺失的快照重新出现，未接管")
		}
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		f.Close()
		if err != nil || st.Size() != entry.Bytes {
			return nil, errors.New("元数据备份大小变化")
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CapturedAt == entries[j].CapturedAt {
			return entries[i].ID > entries[j].ID
		}
		return entries[i].CapturedAt > entries[j].CapturedAt
	})
	return entries, nil
}

func (s *Service) openWAFBodyLogArchive(id string) (*os.File, error) {
	if !core.ValidID(id) {
		return nil, errors.New("元数据备份标识无效")
	}
	directory := s.wafBodyLogArchiveDirectory()
	if err := s.wafOwnedDirectory(directory, false); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, id+".log")
	if err := ownedRuntimePath(path, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > wafBodyLogLimit || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		return nil, errors.New("元数据备份不是私有有界普通文件")
	}
	return f, nil
}

// Snapshot before truncation is durable and exclusive. Same-inode rotation
// does not reload/stop Nginx or touch its ordinary access/error logs. A failed
// commit retains both snapshot and live data; archives are never summed as
// disjoint traffic windows, and an incomplete snapshot blocks further writes.
func (s *Service) rotateWAFBodyLog(ctx context.Context) (wafBodyLogArchive, error) {
	var out wafBodyLogArchive
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return out, err
	}
	defer lock.Close()
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("存在未完成防火墙配置事务，未轮转")
	}
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		return out, err
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return out, err
	}
	if cfg.Body == nil {
		return out, errors.New("请先安全应用本版请求体引擎；旧日志保留且不自动改写")
	}
	if err := s.verifyWAFBodyEngine(cfg); err != nil {
		return out, err
	}
	plan, err := s.planWAFConfiguration(cfg, false)
	if err != nil || len(plan) != 0 {
		return out, errors.New("实际防火墙配置有偏差，请先核对并安全应用")
	}
	return s.snapshotAndTruncateWAFBodyLog(ctx)
}

// Internal filesystem primitive. HTTP can reach it only through the manifest,
// engine, configuration-plan and cross-process lock checks above.
func (s *Service) snapshotAndTruncateWAFBodyLog(ctx context.Context) (wafBodyLogArchive, error) {
	return s.snapshotAndTruncateWAFBodyLogAt(ctx, nil)
}

// Checkpoints are internal fault-injection seams, never caller input or an
// environment switch in production. The ordinary entry point passes nil.
func (s *Service) snapshotAndTruncateWAFBodyLogAt(ctx context.Context, checkpoint func(string) error) (wafBodyLogArchive, error) {
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	var out wafBodyLogArchive
	archives, err := s.wafBodyLogArchives()
	if err != nil {
		return out, err
	}
	if len(archives) >= wafBodyLogArchiveLimit {
		return out, errors.New("元数据备份已达 8 份，未丢弃历史；请先导出并管理备份")
	}
	for _, archive := range archives {
		if archive.State == "prepared" {
			return out, errors.New("上次元数据轮转未确认完成，证据保留，请先核对")
		}
	}
	f, err := s.openWAFBodyLog(true, false)
	if err != nil {
		return out, err
	}
	defer f.Close()
	fl := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl); err != nil {
		return out, errors.New("请求体日志正在写入，请稍后重试")
	}
	defer func() { fl.Type = syscall.F_UNLCK; _ = syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl) }()
	st, err := f.Stat()
	if err != nil {
		return out, err
	}
	if st.Size() == 0 {
		return out, errors.New("当前元数据日志为空，未生成空备份")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	originalHash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(io.LimitReader(f, wafBodyLogLimit+1), originalHash))
	scanner.Buffer(make([]byte, 512), 513)
	for scanner.Scan() {
		if _, ok := parseWAFBodyEvent(scanner.Bytes()); !ok {
			return out, errors.New("元数据日志存在异常内容，保留原文件且未轮转")
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
	}
	if err := scanner.Err(); err != nil {
		return out, errors.New("元数据日志内容超过固定行上限，未轮转")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	directory := s.wafBodyLogArchiveDirectory()
	if err := s.wafBodyLogPrivateDirectory(directory, true); err != nil {
		return out, err
	}
	out = wafBodyLogArchive{ID: core.ID(), CapturedAt: core.Now(), Bytes: st.Size(), State: "copying", SHA256: hex.EncodeToString(originalHash.Sum(nil))}
	// Intent is durable BEFORE creating a potentially partial snapshot.
	if err := s.writeWAFBodyLogIndexAt(ctx, out, func(stage string) error { return mark("intent-" + stage) }); err != nil {
		return out, err
	}
	if err := mark("intent-durable"); err != nil {
		return out, err
	}
	archive, err := os.OpenFile(filepath.Join(directory, out.ID+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return out, err
	}
	if err := mark("snapshot-created"); err != nil {
		archive.Close()
		return out, err
	}
	hash := sha256.New()
	n, copyErr := io.CopyN(io.MultiWriter(archive, hash), f, st.Size())
	syncErr := archive.Sync()
	closeErr := archive.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n != st.Size() {
		return out, errors.New("元数据备份未完整持久化；保留原日志及失败证据，未截断")
	}
	if hex.EncodeToString(hash.Sum(nil)) != out.SHA256 {
		return out, errors.New("日志复制摘要与持久化意图不符，保留原日志及失败证据")
	}
	if err := mark("snapshot-durable"); err != nil {
		return out, err
	}
	out.State = "prepared"
	if err := s.writeWAFBodyLogIndexAt(ctx, out, func(stage string) error { return mark("prepared-" + stage) }); err != nil {
		return out, err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return out, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return out, err
	}
	if err := mark("prepared-durable"); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	// The path must still identify the descriptor; a substituted file is never
	// truncated. Worker ownership changes on USR1 are deliberately supported.
	current, err := os.Lstat(s.systemPath(wafBodyLogPath))
	if err != nil || !os.SameFile(st, current) {
		return out, errors.New("元数据日志路径在备份后变化，未截断")
	}
	if err := f.Truncate(0); err != nil {
		return out, err
	}
	if err := f.Sync(); err != nil {
		return out, err
	}
	if err := mark("truncate-durable"); err != nil {
		return out, err
	}
	out.State = "completed"
	if err := s.writeWAFBodyLogIndexAt(ctx, out, func(stage string) error { return mark("completed-" + stage) }); err != nil {
		return out, errors.New("元数据已备份并轮转，但完成索引写入失败；证据保留，请核对")
	}
	if err := mark("completed-durable"); err != nil {
		return out, err
	}
	return out, nil
}

// Only an explicitly selected, digest-bound private snapshot can be removed.
// No active log, website log, directory, wildcard or caller path is accepted.
func (s *Service) removeWAFBodyLogArchive(ctx context.Context, id, sha string) error {
	return s.removeWAFBodyLogArchiveAt(ctx, id, sha, nil)
}

func (s *Service) removeWAFBodyLogArchiveAt(ctx context.Context, id, sha string, checkpoint func(string) error) error {
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	if !core.ValidID(id) || len(sha) != 64 || strings.Trim(sha, "0123456789abcdef") != "" {
		return errors.New("元数据备份标识或摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := s.wafBodyLogRecoveryEntries(ctx); err != nil {
		return err
	}
	entry, _, err := s.readWAFBodyLogIndex(id)
	if err != nil {
		return err
	}
	if entry.State == "copying" {
		return errors.New("所选快照复制未完成，请先保留恢复证据")
	}
	if entry.State != "removing" {
		if _, err := s.wafBodyLogArchives(); err != nil {
			return err
		}
	}
	if entry.SHA256 != sha {
		return errors.New("备份摘要与所选记录不符，未删除")
	}
	path := filepath.Join(s.wafBodyLogArchiveDirectory(), id+".log")
	f, err := s.openWAFBodyLogArchive(id)
	missing := errors.Is(err, os.ErrNotExist) && (entry.State == "removing" || entry.State == "retained-missing")
	if err != nil && !missing {
		return err
	}
	if !missing {
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		actual, err := wafNativeFileSHA(ctx, path, wafBodyLogLimit)
		if err != nil || actual != sha {
			return errors.New("备份实际摘要变化，未删除")
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(st, current) {
			return errors.New("备份路径发生替换，未删除")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entry.State = "removing"
	index := filepath.Join(s.wafBodyLogArchiveDirectory(), id+".json")
	if err := s.writeWAFBodyLogIndexAt(ctx, entry, func(stage string) error { return mark("remove-" + stage) }); err != nil {
		return err
	}
	if err := mark("remove-intent-durable"); err != nil {
		return err
	}
	directory, err := os.Open(s.wafBodyLogArchiveDirectory())
	if err != nil {
		return err
	}
	defer directory.Close()
	if !missing {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	// Commit the data-file unlink before removing its durable intent.
	// A cold interruption can always retry this exact ID and digest.
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := mark("snapshot-unlink-durable"); err != nil {
		return err
	}
	if err := os.Remove(index); err != nil {
		return errors.New("所选快照已移除，但索引清理失败，请核对；不影响当前日志")
	}
	return directory.Sync()
}
