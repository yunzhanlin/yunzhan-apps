//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const phpQuarantineModule = "php-code-security"
const phpQuarantineMaxFile int64 = 8 << 20
const phpQuarantineMaxRecords = 512
const phpQuarantineMaxBackups int64 = 256 << 20

type phpFileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type phpQuarantineRecord struct {
	ID         string            `json:"id"`
	SiteID     string            `json:"site_id"`
	Path       string            `json:"path"`
	SHA256     string            `json:"sha256"`
	Bytes      int64             `json:"bytes"`
	UID        int               `json:"uid"`
	GID        int               `json:"gid"`
	Mode       uint32            `json:"mode"`
	Attributes map[string][]byte `json:"attributes,omitempty"`
	Site       phpFileIdentity   `json:"site_identity"`
	Public     phpFileIdentity   `json:"public_identity"`
	Parent     phpFileIdentity   `json:"parent_identity"`
	Original   phpFileIdentity   `json:"original_identity"`
	Restored   phpFileIdentity   `json:"restored_identity"`
	StageID    string            `json:"stage_id,omitempty"`
	State      string            `json:"state"`
	Revision   int64             `json:"revision"`
	CreatedAt  string            `json:"created_at"`
	UpdatedAt  string            `json:"updated_at"`
}

func phpIdentity(info os.FileInfo) phpFileIdentity {
	st := info.Sys().(*syscall.Stat_t)
	return phpFileIdentity{uint64(st.Dev), st.Ino}
}

func phpSHA(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func phpValidSHA(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && value == strings.ToLower(value)
}

func phpValidPath(path string) bool {
	if !core.ValidFilePath(path, false) {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".php", ".phtml", ".inc":
		return true
	}
	return false
}

// No fallback to path-based rename or symlink-following open: supported Linux
// kernels must supply openat2 and RENAME_NOREPLACE for this destructive workflow.
func phpOpenAt(dir *os.File, path string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat2(int(dir.Fd()), path, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func phpRenameNoReplace(from *os.File, src string, to *os.File, dst string) error {
	return unix.Renameat2(int(from.Fd()), src, int(to.Fd()), dst, unix.RENAME_NOREPLACE)
}

func phpPrivateDirectory(parent *os.File, name string, create bool) (*os.File, error) {
	if create {
		if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && err != unix.EEXIST {
			return nil, err
		}
		if err := parent.Sync(); err != nil {
			return nil, err
		}
	}
	dir, err := phpOpenAt(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := dir.Stat()
	if err != nil {
		dir.Close()
		return nil, err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || st.Uid != 0 || info.Mode().Perm() != 0700 {
		dir.Close()
		return nil, errors.New("PHP 隔离私有目录身份或权限异常，未自动修正")
	}
	return dir, nil
}

func (s *Service) phpQuarantineRecordDir(create bool) (string, error) {
	base := s.moduleDir(phpQuarantineModule)
	if create {
		if err := os.MkdirAll(base, 0700); err != nil {
			return "", err
		}
	}
	root, err := os.OpenFile(base, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := root.Stat()
	if err != nil {
		return "", err
	}
	if info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return "", errors.New("PHP 模块目录不可由其他用户写入")
	}
	dir, err := phpPrivateDirectory(root, "quarantine", create)
	if err != nil {
		return "", err
	}
	dir.Close()
	return filepath.Join(base, "quarantine"), nil
}

func (s *Service) phpReadQuarantine(id string) (phpQuarantineRecord, error) {
	var q phpQuarantineRecord
	if !core.ValidID(id) {
		return q, errors.New("隔离记录标识无效")
	}
	dir, err := s.phpQuarantineRecordDir(false)
	if err != nil {
		return q, err
	}
	path := filepath.Join(dir, id+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return q, err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm() != 0600 {
		return q, errors.New("隔离记录身份或权限异常")
	}
	if err = moduleRead(path, &q); err != nil {
		return q, err
	}
	if q.ID != id || !core.ValidID(q.SiteID) || !phpValidPath(q.Path) || !phpValidSHA(q.SHA256) || q.Bytes < 0 || q.Bytes > phpQuarantineMaxFile || q.UID <= 0 || q.GID < 0 || q.Mode & ^uint32(0777) != 0 || q.Revision < 1 || q.Site.Inode == 0 || q.Public.Inode == 0 || q.Parent.Inode == 0 || q.Original.Inode == 0 || len(q.Attributes) > 64 {
		return q, errors.New("隔离记录字段异常")
	}
	switch q.State {
	case "prepared", "quarantined", "conflict", "restoring", "restored", "cancelled":
	default:
		return q, errors.New("隔离事务状态无效")
	}
	if q.State == "restoring" && !core.ValidID(q.StageID) {
		return q, errors.New("恢复暂存标识无效")
	}
	attributeBytes := 0
	for key, value := range q.Attributes {
		attributeBytes += len(key) + len(value)
		if key == "security.capability" || key == "" || len(key) > 255 || strings.ContainsRune(key, 0) || attributeBytes > 16384 {
			return q, errors.New("隔离属性记录异常")
		}
	}
	return q, nil
}

func (s *Service) phpSaveQuarantine(q *phpQuarantineRecord, state string) error {
	dir, err := s.phpQuarantineRecordDir(true)
	if err != nil {
		return err
	}
	if q.Revision == 0 {
		if _, err := os.Lstat(filepath.Join(dir, q.ID+".json")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("新的隔离标识已存在或无法确认，未覆盖记录")
		}
	}
	q.State = state
	q.Revision++
	q.UpdatedAt = core.Now()
	return moduleWrite(filepath.Join(dir, q.ID+".json"), q)
}

func (s *Service) phpQuarantineRecords() ([]phpQuarantineRecord, error) {
	dir, err := s.phpQuarantineRecordDir(false)
	if errors.Is(err, os.ErrNotExist) {
		return []phpQuarantineRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(phpQuarantineMaxRecords + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > phpQuarantineMaxRecords {
		return nil, errors.New("隔离记录超过 512 条安全上限，未修改文件")
	}
	rows := []phpQuarantineRecord{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("隔离记录目录包含异常项")
		}
		q, err := s.phpReadQuarantine(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		rows = append(rows, q)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt > rows[j].CreatedAt })
	return rows, nil
}

// Used even after module uninstall: unfinished isolation cannot lose its site.
func (s *Service) phpQuarantineReference(siteID string) error {
	rows, err := s.phpQuarantineRecords()
	if err != nil {
		return err
	}
	for _, q := range rows {
		if (siteID == "" || q.SiteID == siteID) && q.State != "restored" && q.State != "cancelled" {
			return errors.New("PHP 仍有隔离文件或未完成事务；先恢复并核对，备份不会删除")
		}
	}
	return nil
}

type phpQuarantineFiles struct{ site, public, parent, storage *os.File }

func (f *phpQuarantineFiles) Close() {
	for _, v := range []*os.File{f.storage, f.parent, f.public, f.site} {
		if v != nil {
			v.Close()
		}
	}
}

func (s *Service) phpQuarantineFiles(q *phpQuarantineRecord, create bool) (*phpQuarantineFiles, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("隔离操作需要受管 root 执行器")
	}
	f := &phpQuarantineFiles{}
	fail := func(err error) (*phpQuarantineFiles, error) { f.Close(); return nil, err }
	base, err := os.OpenFile(s.Config.SitesDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(err)
	}
	defer base.Close()
	f.site, err = phpOpenAt(base, q.SiteID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(err)
	}
	marker, err := phpOpenAt(f.site, ".panel-site.json", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(err)
	}
	data, err := io.ReadAll(io.LimitReader(marker, 4097))
	marker.Close()
	if err != nil {
		return fail(err)
	}
	var owner map[string]string
	if len(data) > 4096 || json.Unmarshal(data, &owner) != nil || owner["id"] != q.SiteID {
		return fail(errors.New("PHP 隔离网站标识不匹配"))
	}
	f.public, err = phpOpenAt(f.site, "public", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(err)
	}
	f.parent, err = phpOpenAt(f.public, filepath.Dir(q.Path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(err)
	}
	si, err := f.site.Stat()
	if err != nil {
		return fail(err)
	}
	pi, err := f.public.Stat()
	if err != nil {
		return fail(err)
	}
	di, err := f.parent.Stat()
	if err != nil {
		return fail(err)
	}
	st := pi.Sys().(*syscall.Stat_t)
	if st.Uid == 0 || pi.Mode().Perm()&0002 != 0 {
		return fail(errors.New("仅隔离非 root 网站普通目录，拒绝其他用户可写目录"))
	}
	if create {
		q.Site = phpIdentity(si)
		q.Public = phpIdentity(pi)
		q.Parent = phpIdentity(di)
		q.UID = int(st.Uid)
		q.GID = int(st.Gid)
		if q.Site.Device != q.Parent.Device {
			return fail(errors.New("文件父目录与站点私有区域跨文件系统，未分配备份或移动文件"))
		}
	} else if q.Site != phpIdentity(si) || q.Public != phpIdentity(pi) || q.Parent != phpIdentity(di) || q.UID != int(st.Uid) || q.GID != int(st.Gid) {
		return fail(errors.New("网站或原文件父目录身份已变化，未操作替换目录"))
	}
	if create {
		return f, nil
	}
	if err = s.phpAttachQuarantineStorage(q, f, false); err != nil {
		if q.State == "prepared" && errors.Is(err, os.ErrNotExist) {
			return f, nil
		}
		return fail(err)
	}
	return f, nil
}

func (s *Service) phpAttachQuarantineStorage(q *phpQuarantineRecord, f *phpQuarantineFiles, create bool) error {
	private, err := phpPrivateDirectory(f.site, filePrivate, create)
	if err != nil {
		return err
	}
	defer private.Close()
	storage, err := phpPrivateDirectory(private, "php-quarantine", create)
	if err != nil {
		return err
	}
	defer storage.Close()
	f.storage, err = phpPrivateDirectory(storage, q.ID, create)
	if err != nil {
		return err
	}
	storageInfo, err := f.storage.Stat()
	if err != nil {
		return err
	}
	if phpIdentity(storageInfo).Device != q.Parent.Device {
		return errors.New("原文件与隔离目录不在同一文件系统，拒绝非原子移动")
	}
	return nil
}

func phpReadFile(dir *os.File, name string, private bool) ([]byte, os.FileInfo, error) {
	f, err := phpOpenAt(dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	st := before.Sys().(*syscall.Stat_t)
	if !before.Mode().IsRegular() || st.Nlink != 1 || before.Size() < 0 || before.Size() > phpQuarantineMaxFile || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, nil, errors.New("仅允许不超过 8 MiB 的普通单链接文件，拒绝特殊权限")
	}
	if private && (st.Uid != 0 || before.Mode().Perm() != 0600) {
		return nil, nil, errors.New("隔离备份身份或权限异常")
	}
	data, err := io.ReadAll(io.LimitReader(f, phpQuarantineMaxFile+1))
	if err != nil {
		return nil, nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	a := after.Sys().(*syscall.Stat_t)
	if len(data) > int(phpQuarantineMaxFile) || int64(len(data)) != before.Size() || before.Size() != after.Size() || st.Mtim != a.Mtim || st.Ctim != a.Ctim || st.Nlink != a.Nlink {
		return nil, nil, errors.New("读取期间文件发生变化，请重新扫描")
	}
	return data, after, nil
}

func phpAttributes(f *os.File) (map[string][]byte, error) {
	n, err := unix.Flistxattr(int(f.Fd()), nil)
	if err == unix.ENOTSUP {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if n > 16384 {
		return nil, errors.New("文件扩展属性超限")
	}
	buf := make([]byte, n)
	n, err = unix.Flistxattr(int(f.Fd()), buf)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	total := n
	for _, key := range strings.Split(string(buf[:n]), "\x00") {
		if key == "" {
			continue
		}
		if key == "security.capability" {
			return nil, errors.New("拒绝含可执行权限 capability 的 PHP 文件")
		}
		n, err = unix.Fgetxattr(int(f.Fd()), key, nil)
		if err != nil {
			return nil, err
		}
		total += n
		if total > 16384 || len(out) >= 64 {
			return nil, errors.New("文件扩展属性超限")
		}
		v := make([]byte, n)
		n, err = unix.Fgetxattr(int(f.Fd()), key, v)
		if err != nil {
			return nil, err
		}
		out[key] = v[:n]
	}
	return out, nil
}

func phpWritePrivate(dir *os.File, name string, data []byte) (*os.File, error) {
	f, err := phpOpenAt(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chown(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = dir.Sync()
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func phpAbsent(dir *os.File, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) == unix.ENOENT
}

func (s *Service) phpPrepareQuarantine(ctx context.Context, in core.AppModuleInput) (phpQuarantineRecord, *phpQuarantineFiles, error) {
	q := phpQuarantineRecord{ID: core.ID(), SiteID: in.SiteID, Path: in.Path, CreatedAt: core.Now()}
	if !core.ValidID(in.SiteID) || !phpValidPath(in.Path) || !phpValidSHA(in.ExpectedSHA) || in.Confirm != "QUARANTINE "+in.Path {
		return q, nil, errors.New("选择 PHP 文件和当前摘要，并填写 QUARANTINE 相对文件路径")
	}
	if err := ctx.Err(); err != nil {
		return q, nil, err
	}
	rows, err := s.phpQuarantineRecords()
	if err != nil {
		return q, nil, err
	}
	var bytes int64
	for _, v := range rows {
		bytes += v.Bytes
		if v.SiteID == in.SiteID && v.Path == in.Path && v.State != "restored" && v.State != "cancelled" {
			return q, nil, errors.New("该文件已有隔离或未完成记录，请先核对现有事务")
		}
	}
	if len(rows) >= phpQuarantineMaxRecords {
		return q, nil, errors.New("已达 512 条隔离记录上限，保留全部备份，未修改文件")
	}
	f, err := s.phpQuarantineFiles(&q, true)
	if err != nil {
		return q, nil, err
	}
	fail := func(err error) (phpQuarantineRecord, *phpQuarantineFiles, error) { f.Close(); return q, nil, err }
	data, info, err := phpReadFile(f.parent, filepath.Base(q.Path), false)
	if err != nil {
		return fail(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if int(st.Uid) != q.UID || int(st.Gid) != q.GID || info.Mode().Perm()&0002 != 0 {
		return fail(errors.New("文件所有者与网站身份不匹配或其他用户可写，未隔离"))
	}
	q.SHA256 = phpSHA(data)
	q.Bytes = int64(len(data))
	q.Mode = uint32(info.Mode().Perm())
	q.Original = phpIdentity(info)
	if q.SHA256 != in.ExpectedSHA {
		return fail(errors.New("文件摘要已变化，请重新扫描后选择，不隔离新内容"))
	}
	if bytes+q.Bytes > phpQuarantineMaxBackups {
		return fail(errors.New("隔离备份已达 256 MiB 安全预算，保留现有数据，未修改文件"))
	}
	original, err := phpOpenAt(f.parent, filepath.Base(q.Path), unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(err)
	}
	current, err := original.Stat()
	if err == nil && !phpSameSnapshot(info, current) {
		err = errors.New("属性读取前文件身份发生变化")
	}
	if err == nil {
		q.Attributes, err = phpAttributes(original)
	}
	if err == nil {
		after, statErr := original.Stat()
		if statErr != nil {
			err = statErr
		} else if !phpSameSnapshot(info, after) {
			err = errors.New("属性读取期间文件发生变化")
		}
	}
	original.Close()
	if err != nil {
		return fail(err)
	}
	// Reserve record/count/byte budgets durably before allocating any backup.
	// If interrupted here, recovery cancels the uncommitted move without
	// requiring a backup which may not yet have been written.
	if err = s.phpSaveQuarantine(&q, "prepared"); err != nil {
		return fail(err)
	}
	if err = s.phpAttachQuarantineStorage(&q, f, true); err != nil {
		return fail(err)
	}
	backup, err := phpWritePrivate(f.storage, "backup.bin", data)
	if err != nil {
		return fail(err)
	}
	backup.Close()
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return q, f, nil
}

func phpSameSnapshot(a, b os.FileInfo) bool {
	x, y := a.Sys().(*syscall.Stat_t), b.Sys().(*syscall.Stat_t)
	return phpIdentity(a) == phpIdentity(b) && a.Mode() == b.Mode() && a.Size() == b.Size() && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Ctim == y.Ctim && x.Mtim == y.Mtim
}

func (s *Service) phpCurrentDirectories(q *phpQuarantineRecord) error {
	f, err := s.phpQuarantineFiles(q, false)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

func (s *Service) phpRollbackMoved(q *phpQuarantineRecord, f *phpQuarantineFiles, cause error) error {
	if err := phpRenameNoReplace(f.storage, "moved.bin", f.parent, filepath.Base(q.Path)); err != nil {
		if save := s.phpSaveQuarantine(q, "conflict"); save != nil {
			return fmt.Errorf("移动冲突和记录保存失败，私有文件与备份保留：%w", save)
		}
		return fmt.Errorf("并发文件变化且原位置冲突，未覆盖两份文件；请恢复中断事务：%w", cause)
	}
	if err := f.parent.Sync(); err != nil {
		return err
	}
	if err := f.storage.Sync(); err != nil {
		return err
	}
	if err := s.phpSaveQuarantine(q, "cancelled"); err != nil {
		return err
	}
	return fmt.Errorf("文件并发变化，已将移动的版本无覆盖回放，独立备份保留：%w", cause)
}

func (s *Service) phpFinishQuarantine(q *phpQuarantineRecord, f *phpQuarantineFiles) error {
	if err := s.phpCurrentDirectories(q); err != nil {
		return err
	}
	backup, _, backupErr := phpReadFile(f.storage, "backup.bin", true)
	if backupErr != nil || phpSHA(backup) != q.SHA256 {
		return errors.New("提交前私有备份验证失败，原文件未移动")
	}
	// Validate again before moving. A simultaneous last-component replacement is
	// captured by the post-rename inode/hash check, never by deleting a pathname.
	data, info, err := phpReadFile(f.parent, filepath.Base(q.Path), false)
	if err != nil || !phpOriginalMatches(q, info, data) {
		if save := s.phpSaveQuarantine(q, "cancelled"); save != nil {
			return save
		}
		return errors.New("隔离提交前文件变化，未移动当前文件；已保留独立备份")
	}
	if err = phpRenameNoReplace(f.parent, filepath.Base(q.Path), f.storage, "moved.bin"); err != nil {
		return fmt.Errorf("原子移动失败，prepared 记录可恢复，原位置未覆盖：%w", err)
	}
	if err = f.parent.Sync(); err != nil {
		return err
	}
	if err = f.storage.Sync(); err != nil {
		return err
	}
	data, info, err = phpReadFile(f.storage, "moved.bin", false)
	if err != nil || !phpOriginalMatches(q, info, data) {
		return s.phpRollbackMoved(q, f, errors.New("移动后 inode 或摘要不匹配"))
	}
	moved, err := phpOpenAt(f.storage, "moved.bin", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer moved.Close()
	if err = moved.Chown(0, 0); err != nil {
		return err
	}
	if err = moved.Chmod(0600); err != nil {
		return err
	}
	if err = moved.Sync(); err != nil {
		return err
	}
	return s.phpSaveQuarantine(q, "quarantined")
}

func phpOriginalMatches(q *phpQuarantineRecord, info os.FileInfo, data []byte) bool {
	st := info.Sys().(*syscall.Stat_t)
	return phpIdentity(info) == q.Original && phpSHA(data) == q.SHA256 && int(st.Uid) == q.UID && int(st.Gid) == q.GID && uint32(info.Mode().Perm()) == q.Mode
}

func (s *Service) phpRestoreStage(q *phpQuarantineRecord, f *phpQuarantineFiles) error {
	data, _, err := phpReadFile(f.storage, "backup.bin", true)
	if err != nil || phpSHA(data) != q.SHA256 || int64(len(data)) != q.Bytes {
		return errors.New("隔离独立备份损坏或身份异常，未恢复或覆盖网站文件")
	}
	if q.Restored.Inode == 0 {
		// Incomplete private staging writes are retained, not overwritten. A new
		// attempt has a new ID durably recorded before creating its private file.
		if !phpAbsent(f.storage, "restore-"+q.StageID+".bin") {
			entries, readErr := f.storage.ReadDir(9)
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			if len(entries) >= 8 {
				return errors.New("恢复暂存文件已达安全上限，保留所有版本，请核对私有备份")
			}
			q.StageID = core.ID()
			if err = s.phpSaveQuarantine(q, "restoring"); err != nil {
				return err
			}
		}
		stage, err := phpWritePrivate(f.storage, "restore-"+q.StageID+".bin", data)
		if err != nil {
			return err
		}
		if err = stage.Chown(q.UID, q.GID); err == nil {
			err = stage.Chmod(os.FileMode(q.Mode))
		}
		if err == nil {
			currentAttributes, attributeErr := phpAttributes(stage)
			if attributeErr != nil {
				err = attributeErr
			} else {
				for key := range currentAttributes {
					if _, present := q.Attributes[key]; !present {
						if err = unix.Fremovexattr(int(stage.Fd()), key); err != nil {
							break
						}
					}
				}
			}
		}
		if err == nil {
			for key, value := range q.Attributes {
				if err = unix.Fsetxattr(int(stage.Fd()), key, value, 0); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = stage.Sync()
		}
		info, statErr := stage.Stat()
		stage.Close()
		if err != nil {
			return err
		}
		if statErr != nil {
			return statErr
		}
		q.Restored = phpIdentity(info)
		if err = s.phpSaveQuarantine(q, "restoring"); err != nil {
			return err
		}
	}
	stageName := "restore-" + q.StageID + ".bin"
	data, info, err := phpReadFile(f.storage, stageName, false)
	if err != nil || phpIdentity(info) != q.Restored || phpSHA(data) != q.SHA256 {
		return errors.New("恢复暂存文件异常，未覆盖网站文件")
	}
	st := info.Sys().(*syscall.Stat_t)
	if int(st.Uid) != q.UID || int(st.Gid) != q.GID || uint32(info.Mode().Perm()) != q.Mode {
		return errors.New("恢复暂存权限异常")
	}
	if err = s.phpCurrentDirectories(q); err != nil {
		return err
	}
	if err = phpRenameNoReplace(f.storage, stageName, f.parent, filepath.Base(q.Path)); err != nil {
		return fmt.Errorf("恢复目标已存在或不支持安全移动，未覆盖原位置；可核对后恢复事务：%w", err)
	}
	if err = f.parent.Sync(); err != nil {
		return err
	}
	if err = f.storage.Sync(); err != nil {
		return err
	}
	return s.phpSaveQuarantine(q, "restored")
}

func (s *Service) phpRecoverQuarantine(q *phpQuarantineRecord, f *phpQuarantineFiles) error {
	name := filepath.Base(q.Path)
	if q.State == "restoring" {
		if !phpAbsent(f.parent, name) {
			data, info, err := phpReadFile(f.parent, name, false)
			if err != nil || q.Restored.Inode == 0 || phpIdentity(info) != q.Restored || phpSHA(data) != q.SHA256 {
				return errors.New("恢复原位置出现其他文件，未覆盖或移动新文件")
			}
			if err = f.parent.Sync(); err != nil {
				return err
			}
			if err = f.storage.Sync(); err != nil {
				return err
			}
			return s.phpSaveQuarantine(q, "restored")
		}
		return s.phpRestoreStage(q, f)
	}
	if q.State != "prepared" && q.State != "conflict" {
		return errors.New("记录没有待恢复的中断事务")
	}
	if f.storage == nil || phpAbsent(f.storage, "moved.bin") {
		if phpAbsent(f.parent, name) {
			return errors.New("原文件和移动文件均缺失，保留备份，需核对文件来源")
		}
		return s.phpSaveQuarantine(q, "cancelled") // Rename never took place; keep current public file.
	}
	backup, _, err := phpReadFile(f.storage, "backup.bin", true)
	if err != nil || phpSHA(backup) != q.SHA256 {
		return errors.New("隔离独立备份异常，未恢复事务")
	}
	data, info, err := phpReadFile(f.storage, "moved.bin", false)
	if err != nil || phpIdentity(info) != q.Original || phpSHA(data) != q.SHA256 {
		return s.phpRollbackMoved(q, f, errors.New("中断期间移动文件与已审查身份不符"))
	}
	moved, err := phpOpenAt(f.storage, "moved.bin", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer moved.Close()
	if err = moved.Chown(0, 0); err != nil {
		return err
	}
	if err = moved.Chmod(0600); err != nil {
		return err
	}
	if err = moved.Sync(); err != nil {
		return err
	}
	return s.phpSaveQuarantine(q, "quarantined")
}

func phpQuarantineRow(q phpQuarantineRecord) map[string]any {
	return map[string]any{"id": q.ID, "site_id": q.SiteID, "path": q.Path, "sha256": q.SHA256, "bytes": q.Bytes, "mode": fmt.Sprintf("%04o", q.Mode), "uid": q.UID, "gid": q.GID, "state": q.State, "revision": q.Revision, "created_at": q.CreatedAt, "updated_at": q.UpdatedAt}
}

func (s *Service) phpListQuarantine(in core.AppModuleInput) (any, error) {
	if in.SiteID != "" && !core.ValidID(in.SiteID) || len(in.Search) > 128 || in.Offset < 0 || in.Offset > phpQuarantineMaxRecords || in.Limit < 0 || in.Limit > 200 {
		return nil, errors.New("隔离清单筛选无效")
	}
	rows, err := s.phpQuarantineRecords()
	if err != nil {
		return nil, err
	}
	limit := in.Limit
	if limit == 0 {
		limit = 50
	}
	filtered := []phpQuarantineRecord{}
	bytes := int64(0)
	pending, active := 0, 0
	for _, q := range rows {
		bytes += q.Bytes
		if q.State == "prepared" || q.State == "conflict" || q.State == "restoring" {
			pending++
		}
		if q.State == "quarantined" {
			active++
		}
		if in.SiteID != "" && q.SiteID != in.SiteID {
			continue
		}
		if in.Search != "" && !strings.Contains(strings.ToLower(q.Path+" "+q.ID+" "+q.State), strings.ToLower(in.Search)) {
			continue
		}
		filtered = append(filtered, q)
	}
	out := []map[string]any{}
	for _, q := range filtered[min(in.Offset, len(filtered)):min(in.Offset+limit, len(filtered))] {
		row := phpQuarantineRow(q)
		f, openErr := s.phpQuarantineFiles(&q, false)
		if openErr != nil {
			row["backup_error"] = "网站目录或隔离私有目录身份异常"
		} else if f.storage == nil {
			row["source_present"] = !phpAbsent(f.parent, filepath.Base(q.Path))
			row["backup_verified"] = false
			row["backup_error"] = "中断的准备事务尚未创建备份，原文件未移动"
			f.Close()
		} else {
			row["source_present"] = !phpAbsent(f.parent, filepath.Base(q.Path))
			data, _, backupErr := phpReadFile(f.storage, "backup.bin", true)
			row["backup_verified"] = backupErr == nil && phpSHA(data) == q.SHA256
			if backupErr != nil || phpSHA(data) != q.SHA256 {
				row["backup_error"] = "隔离独立备份验证失败"
			}
			f.Close()
		}
		out = append(out, row)
	}
	return map[string]any{"quarantine": out, "total": len(filtered), "limit": limit, "offset": in.Offset, "retained_count": len(rows), "backup_bytes": bytes, "record_limit": phpQuarantineMaxRecords, "backup_budget_bytes": phpQuarantineMaxBackups, "pending_transactions": pending, "quarantined_count": active, "interpretation": "人工确认后才移动已审查文件；私有独立备份保留，恢复不覆盖原位置。不是持续内核拦截：原路径可被其他程序重新创建，已执行请求或 PHP OPcache 不会被自动终止。"}, nil
}

func (s *Service) modulePHPQuarantine(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if action == "run" {
		return s.modulePHPScanFiltered(ctx, in)
	}
	if action == "quarantine-list" {
		return s.phpListQuarantine(in)
	}
	if action != "quarantine" && action != "restore-quarantine" && action != "recover-quarantine" {
		return nil, errors.New("PHP 安全操作无效")
	}
	if action == "quarantine" {
		if !core.ValidID(in.SiteID) {
			return nil, errors.New("请选择网站")
		}
		lock := fileMutex(in.SiteID)
		lock.Lock()
		defer lock.Unlock()
		q, f, err := s.phpPrepareQuarantine(ctx, in)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err = s.phpFinishQuarantine(&q, f); err != nil {
			return nil, err
		}
		return map[string]any{"record": phpQuarantineRow(q), "quarantined_count": 1, "independent_backup_retained": true, "runtime_processes_changed": false}, nil
	}
	q, err := s.phpReadQuarantine(in.ResourceID)
	if err != nil {
		return nil, err
	}
	if in.SiteID != q.SiteID || in.Path != q.Path || in.ExpectedSHA != q.SHA256 || in.ExpectedRevision != q.Revision {
		return nil, errors.New("隔离记录身份、路径、摘要或修订号已变化，请刷新并重新选择")
	}
	want := "RESTORE PHP " + q.ID
	if action == "recover-quarantine" {
		want = "RECOVER PHP " + q.ID
	}
	if in.Confirm != want {
		return nil, fmt.Errorf("请填写 %s", want)
	}
	lock := fileMutex(q.SiteID)
	lock.Lock()
	defer lock.Unlock()
	f, err := s.phpQuarantineFiles(&q, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if action == "recover-quarantine" {
		err = s.phpRecoverQuarantine(&q, f)
	} else {
		if q.State != "quarantined" {
			return nil, errors.New("仅恢复已隔离文件；中断事务请先恢复事务")
		}
		if !phpAbsent(f.parent, filepath.Base(q.Path)) {
			return nil, errors.New("原位置已存在文件，未覆盖；请先核对和移走新文件")
		}
		q.StageID = core.ID()
		q.Restored = phpFileIdentity{}
		if err = s.phpSaveQuarantine(&q, "restoring"); err == nil {
			err = s.phpRestoreStage(&q, f)
		}
	}
	if err != nil {
		return nil, err
	}
	restored := 0
	if q.State == "restored" {
		restored = 1
	}
	return map[string]any{"record": phpQuarantineRow(q), "restored_count": restored, "restored": q.State == "restored", "independent_backup_retained": true, "runtime_processes_changed": false}, nil
}
