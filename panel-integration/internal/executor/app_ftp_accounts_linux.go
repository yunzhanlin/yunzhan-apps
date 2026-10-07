//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type ftpAccountLimits struct {
	QuotaMB, QuotaFiles, UploadKB, DownloadKB, MaxSessions int
	ClientAllow, ClientDeny                                []string
}

func ftpClientNetworks(values []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	if len(values) > 16 {
		return nil, errors.New("允许与拒绝清单各最多 16 个 IPv4/CIDR，不支持 DNS 名称")
	}
	for _, value := range values {
		var canonical string
		if strings.Contains(value, "/") {
			p, e := netip.ParsePrefix(value)
			if e != nil || !p.Addr().Is4() || p.Addr().IsMulticast() {
				return nil, errors.New("客户端清单只允许 IPv4/CIDR")
			}
			canonical = p.Masked().String()
		} else {
			ip, e := netip.ParseAddr(value)
			if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
				return nil, errors.New("客户端清单只允许 IPv4/CIDR")
			}
			canonical = ip.String()
		}
		if !seen[canonical] {
			out = append(out, canonical)
			seen[canonical] = true
		}
	}
	return out, nil
}
func validatedFTPLimits(in core.AppModuleInput) (ftpAccountLimits, error) {
	v := ftpAccountLimits{in.QuotaMB, in.QuotaFiles, in.UploadKB, in.DownloadKB, in.MaxSessions, nil, nil}
	if v.QuotaMB < 0 || v.QuotaMB > 1048576 || v.QuotaFiles < 0 || v.QuotaFiles > 1000000 || v.UploadKB < 0 || v.UploadKB > 1048576 || v.DownloadKB < 0 || v.DownloadKB > 1048576 || v.MaxSessions < 0 || v.MaxSessions > 20 {
		return v, errors.New("容量 0–1048576 MiB，文件与目录 0–1000000，限速 0–1048576 KiB/s，会话 0–20；0 不限制")
	}
	var e error
	if v.ClientAllow, e = ftpClientNetworks(in.ClientAllow); e != nil {
		return v, e
	}
	v.ClientDeny, e = ftpClientNetworks(in.ClientDeny)
	return v, e
}
func ftpLimitsFromFields(fields []string) (ftpAccountLimits, error) {
	v := ftpAccountLimits{ClientAllow: []string{}, ClientDeny: []string{}}
	read := func(i int, divisor int64) (int, error) {
		if len(fields) <= i || fields[i] == "" {
			return 0, nil
		}
		n, e := strconv.ParseInt(fields[i], 10, 64)
		if e != nil || n < 0 || n > 1<<50 {
			return 0, errors.New("FTP 账户限制格式损坏")
		}
		return int(n / divisor), nil
	}
	var e error
	for _, item := range []struct {
		index   int
		divisor int64
		to      *int
	}{{6, 1024, &v.UploadKB}, {7, 1024, &v.DownloadKB}, {10, 1, &v.MaxSessions}, {11, 1, &v.QuotaFiles}, {12, 1048576, &v.QuotaMB}} {
		if *item.to, e = read(item.index, item.divisor); e != nil {
			return v, e
		}
	}
	for _, item := range []struct {
		index int
		to    *[]string
	}{{15, &v.ClientAllow}, {16, &v.ClientDeny}} {
		if len(fields) > item.index && fields[item.index] != "" {
			*item.to = strings.Split(fields[item.index], ",")
		}
	}
	return v, nil // Existing externally-created restrictions are shown, not silently rewritten.
}
func (v ftpAccountLimits) arguments() []string {
	number := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	return []string{"-N", number(v.QuotaMB), "-n", number(v.QuotaFiles), "-T", number(v.UploadKB), "-t", number(v.DownloadKB), "-y", number(v.MaxSessions), "-r", strings.Join(v.ClientAllow, ","), "-R", strings.Join(v.ClientDeny, ",")}
}

type ftpAccountTransaction struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Username    string `json:"username"`
	Action      string `json:"action"`
	Time        string `json:"time"`
	OldText     []byte `json:"old_text"`
	OldDB       []byte `json:"old_db"`
	NextTextSHA string `json:"next_text_sha"`
	NextDBSHA   string `json:"next_db_sha"`
}

func (s *Service) finishFTPAccounts(t ftpAccountTransaction) error {
	dir := s.moduleDir("pure-ftpd")
	pending := filepath.Join(dir, "pending-accounts.json")
	if e := moduleWrite(pending, t); e != nil {
		return e
	}
	if e := moduleWrite(filepath.Join(dir, "account-transactions", t.ID+".json"), t); e != nil {
		return e
	}
	return os.Remove(pending)
}
func (s *Service) recoverFTPAccounts() error {
	dir := s.moduleDir("pure-ftpd")
	data, e := ftpPrivateRead(filepath.Join(dir, "pending-accounts.json"), 8<<20)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var t ftpAccountTransaction
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&t) != nil || d.Decode(&struct{}{}) != io.EOF || !core.ValidID(t.ID) || (t.State != "applying" && t.State != "committed" && t.State != "recovered") || len(t.OldText) > 1<<20 || len(t.OldDB) > 4<<20 {
		return errors.New("FTP 账户恢复记录损坏")
	}
	if t.State != "applying" {
		return s.finishFTPAccounts(t)
	}
	for _, item := range []struct {
		name string
		old  []byte
		next string
	}{{"users.passwd", t.OldText, t.NextTextSHA}, {"users.pdb", t.OldDB, t.NextDBSHA}} {
		current, e := ftpPrivateRead(filepath.Join(dir, item.name), 4<<20)
		if e != nil {
			return e
		}
		sha := core.Hash(string(current))
		if sha != item.next && sha != core.Hash(string(item.old)) {
			return errors.New("FTP 账户数据库被外部修改，拒绝覆盖；恢复记录已保留")
		}
	}
	if _, e := ftpPublicUsers(t.OldText, s.Config.SitesDir); e != nil {
		return e
	}
	if e := atomicWrite(filepath.Join(dir, "users.passwd"), t.OldText, 0600); e != nil {
		return e
	}
	if e := atomicWrite(filepath.Join(dir, "users.pdb"), t.OldDB, 0600); e != nil {
		return e
	}
	t.State = "recovered"
	return s.finishFTPAccounts(t)
}
func ftpFindAccount(users []map[string]any, username string) (map[string]any, error) {
	for _, row := range users {
		if row["username"] == username {
			return row, nil
		}
	}
	return nil, errors.New("FTP 账户不存在，请刷新列表")
}
func (s *Service) mutateFTPAccount(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	lock, e := s.lockFTP()
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	dir := s.moduleDir("pure-ftpd")
	if s.ftpRecoveryPending() {
		return nil, errors.New("FTP 有待恢复事务，请先恢复并刷新")
	}
	oldText, e := ftpPrivateRead(filepath.Join(dir, "users.passwd"), 1<<20)
	if e != nil {
		return nil, e
	}
	oldDB, e := ftpPrivateRead(filepath.Join(dir, "users.pdb"), 4<<20)
	if e != nil {
		return nil, e
	}
	users, e := ftpPublicUsers(oldText, s.Config.SitesDir)
	if e != nil {
		return nil, e
	}
	if action == "account-limits" || action == "recount-quota" {
		if s.Config.SystemRoot == "/" {
			binary, e := s.ftpBinary("pure-ftpd")
			if e != nil || !strings.Contains(binary, ftpRuntimeVersion) {
				return nil, errors.New("账户限额需先在软件商店更新 FTP 到受管独立运行时；旧服务不会静默替换")
			}
		}
		row, e := ftpFindAccount(users, in.Username)
		if e != nil {
			return nil, e
		}
		if in.ExpectedSHA == "" || in.ExpectedSHA != row["expected_sha"] {
			return nil, errors.New("FTP 账户已变化，请刷新并重新选择账户")
		}
		siteID, _ := row["site_id"].(string)
		if !core.ValidID(siteID) {
			return nil, errors.New("只允许管理属于面板网站的 FTP 配额")
		}
		f, e := s.openFiles(siteID)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		if f.uid == 0 || f.uid != row["uid"] || f.gid != row["gid"] {
			return nil, errors.New("FTP 账户与网站身份不一致")
		}
		if action == "recount-quota" {
			return s.recountFTPQuota(ctx, f, in.Username)
		}
		limits, e := validatedFTPLimits(in)
		if e != nil {
			return nil, e
		}
		if limits.QuotaMB > 0 || limits.QuotaFiles > 0 {
			if _, _, e = readFTPQuota(f); e != nil {
				return nil, errors.New("启用配额前请先停止 FTP 并重新统计容量，避免漏算既有文件")
			}
		}
	}
	if action != "create" && action != "password" && action != "delete" && action != "account-limits" {
		return nil, errors.New("FTP 账户操作无效")
	}
	if action == "create" && len(users) >= 1000 {
		return nil, errors.New("FTP 账户数量达到 1000 上限")
	}
	rows, e := filepath.Glob(filepath.Join(dir, "account-transactions", "*.json"))
	if e != nil || len(rows) >= 512 {
		return nil, errors.New("FTP 账户恢复记录达到上限，先归档旧备份")
	}
	// Initialize the fixed boot recovery unit before creating a new journal.
	if s.Config.SystemRoot == "/" {
		if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "start", "panel-pure-ftpd-recover.service"); e != nil {
			return nil, e
		}
	}
	stage, e := os.MkdirTemp(dir, ".account-stage-")
	if e != nil {
		return nil, e
	}
	text, db := filepath.Join(stage, "users.passwd"), filepath.Join(stage, "users.pdb")
	defer func() { _ = os.Remove(text); _ = os.Remove(db); _ = os.Remove(stage) }()
	if e = atomicWrite(text, oldText, 0600); e != nil {
		return nil, e
	}
	if e = s.ftpAccountCommand(ctx, action, in, text); e != nil {
		return nil, e
	}
	if e = os.Chmod(text, 0600); e != nil {
		return nil, e
	}
	binary, e := s.ftpBinary("pure-pw")
	if e != nil {
		return nil, e
	}
	if _, e = s.moduleCommand(ctx, 20*time.Second, binary, "mkdb", db, "-f", text); e != nil {
		return nil, errors.New("FTP 索引构建失败，未改变实际账户")
	}
	if e = os.Chmod(db, 0600); e != nil {
		return nil, e
	}
	nextText, e := ftpPrivateRead(text, 1<<20)
	if e != nil {
		return nil, e
	}
	nextDB, e := ftpPrivateRead(db, 4<<20)
	if e != nil {
		return nil, e
	}
	if _, e = ftpPublicUsers(nextText, s.Config.SitesDir); e != nil {
		return nil, e
	}
	// Reject external changes even when staging took time.
	currentText, e := ftpPrivateRead(filepath.Join(dir, "users.passwd"), 1<<20)
	if e != nil || !bytes.Equal(currentText, oldText) {
		return nil, errors.New("FTP 账户源文件在操作期间变化，未覆盖")
	}
	currentDB, e := ftpPrivateRead(filepath.Join(dir, "users.pdb"), 4<<20)
	if e != nil || !bytes.Equal(currentDB, oldDB) {
		return nil, errors.New("FTP 索引在操作期间变化，未覆盖")
	}
	t := ftpAccountTransaction{ID: core.ID(), State: "applying", Username: in.Username, Action: action, Time: core.Now(), OldText: oldText, OldDB: oldDB, NextTextSHA: core.Hash(string(nextText)), NextDBSHA: core.Hash(string(nextDB))}
	if e = moduleWrite(filepath.Join(dir, "pending-accounts.json"), t); e != nil {
		return nil, e
	}
	rollback := func(cause error) (any, error) {
		if e := s.recoverFTPAccounts(); e != nil {
			return nil, errors.New("FTP 账户提交失败，自动恢复未完成；备份已保留")
		}
		return nil, cause
	}
	if e = atomicWrite(filepath.Join(dir, "users.passwd"), nextText, 0600); e != nil {
		return rollback(e)
	}
	if e = atomicWrite(filepath.Join(dir, "users.pdb"), nextDB, 0600); e != nil {
		return rollback(e)
	}
	t.State = "committed"
	if e = s.finishFTPAccounts(t); e != nil {
		return nil, errors.New("FTP 账户可能已应用，但提交记录保存失败，请刷新并保留恢复记录")
	}
	return map[string]any{"ok": true, "username": in.Username, "action": action, "backup_id": t.ID, "new_connections_only": true}, nil
}

func readFTPQuota(f *siteFiles) (uint64, uint64, error) {
	file, e := regularFile(f.public, ".ftpquota")
	if e != nil {
		return 0, 0, e
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil {
		return 0, 0, e
	}
	st := info.Sys().(*syscall.Stat_t)
	if int(st.Uid) != f.uid || st.Nlink != 1 || info.Size() > 128 {
		return 0, 0, errors.New("FTP 容量计数文件身份不符")
	}
	data, e := io.ReadAll(io.LimitReader(file, 129))
	if e != nil {
		return 0, 0, e
	}
	parts := strings.Fields(string(data))
	if len(parts) != 2 {
		return 0, 0, errors.New("FTP 容量计数格式无效")
	}
	count, e := strconv.ParseUint(parts[0], 10, 64)
	if e != nil {
		return 0, 0, e
	}
	size, e := strconv.ParseUint(parts[1], 10, 64)
	return count, size, e
}

// FTP uses a shared home-directory soft counter, not a kernel disk quota.
// Walk pinned parent descriptors, never symlinks; reject mount points, special
// files, hard links and oversized scans rather than report partial usage.
func scanFTPQuota(ctx context.Context, dir *os.File, device uint64, depth int) (uint64, uint64, error) {
	if depth > 64 {
		return 0, 0, errors.New("FTP 容量目录层级超过 64")
	}
	var count, size uint64
	for {
		entries, e := dir.ReadDir(256)
		if e != nil && e != io.EOF {
			return 0, 0, e
		}
		for _, entry := range entries {
			if e := ctx.Err(); e != nil {
				return 0, 0, e
			}
			if entry.Name() == ".ftpquota" {
				continue
			}
			var st unix.Stat_t
			if e := unix.Fstatat(int(dir.Fd()), entry.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return 0, 0, e
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				continue
			}
			if uint64(st.Dev) != device {
				return 0, 0, errors.New("FTP 容量扫描不跨越文件系统挂载点")
			}
			count++
			if count > 100000 {
				return 0, 0, errors.New("FTP 容量重统计最多 100000 项")
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				fd, e := unix.Openat(int(dir.Fd()), entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if e != nil {
					return 0, 0, e
				}
				child := os.NewFile(uintptr(fd), entry.Name())
				childInfo, e := child.Stat()
				if e != nil || childInfo.Sys().(*syscall.Stat_t).Ino != st.Ino {
					child.Close()
					return 0, 0, errors.New("FTP 扫描目录在操作期间变化")
				}
				n, b, e := scanFTPQuota(ctx, child, device, depth+1)
				child.Close()
				if e != nil {
					return 0, 0, e
				}
				count += n
				size += b
			case unix.S_IFREG:
				if st.Nlink != 1 || st.Size < 0 {
					return 0, 0, errors.New("FTP 容量扫描拒绝硬链接")
				}
				size += uint64(st.Size)
			default:
				return 0, 0, errors.New("FTP 容量扫描拒绝特殊文件")
			}
			if count > 100000 || size > 1<<50 {
				return 0, 0, errors.New("FTP 容量重统计超出安全扫描上限")
			}
		}
		if e == io.EOF {
			break
		}
	}
	return count, size, nil
}
func (s *Service) recountFTPQuota(ctx context.Context, f *siteFiles, username string) (any, error) {
	state, e := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pure-ftpd.service")
	if strings.TrimSpace(state) == "active" || strings.TrimSpace(state) == "activating" || (e != nil && strings.TrimSpace(state) != "inactive" && strings.TrimSpace(state) != "failed") {
		return nil, errors.New("重新统计容量前必须停止 FTP，防止活动传输改变计数；不会自动中断连接")
	}
	scanCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dir, e := f.public.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	info, e := dir.Stat()
	if e != nil {
		return nil, e
	}
	device := uint64(info.Sys().(*syscall.Stat_t).Dev)
	count, size, e := scanFTPQuota(scanCtx, dir, device, 0)
	if e != nil {
		return nil, e
	}
	// Open relative to the pinned root, and never follow a counter symlink.
	fd, e := unix.Openat(int(dir.Fd()), ".ftpquota", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	counter := os.NewFile(uintptr(fd), ".ftpquota")
	defer counter.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > 128 || (int(st.Uid) != f.uid && !(st.Size == 0 && st.Uid == 0)) {
		return nil, errors.New("FTP 容量计数文件身份或类型异常，未覆盖")
	}
	if e = unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}); e != nil {
		return nil, errors.New("FTP 容量计数正在使用，未覆盖")
	}
	previous, e := io.ReadAll(io.LimitReader(counter, 129))
	if e != nil {
		return nil, e
	}
	backupID := core.ID()
	backups, e := filepath.Glob(filepath.Join(s.moduleDir("pure-ftpd"), "quota-backups", "*.json"))
	if e != nil || len(backups) >= 512 {
		return nil, errors.New("FTP 容量备份达到上限，请先归档旧备份")
	}
	if e = moduleWrite(filepath.Join(s.moduleDir("pure-ftpd"), "quota-backups", backupID+".json"), map[string]any{"id": backupID, "username": username, "time": core.Now(), "old_counter": string(previous), "files": count, "bytes": size}); e != nil {
		return nil, e
	}
	// Never truncate the live counter: disk-full, process interruption and
	// failed writes leave the old complete value visible. Atomic replacement
	// is safe only with the FTP unit stopped; this is still a soft counter.
	name := ".panel-ftpquota-" + backupID
	nextFD, e := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	next := os.NewFile(uintptr(nextFD), name)
	defer next.Close()
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	if _, e = fmt.Fprintf(next, "%d %d\n", count, size); e != nil {
		return nil, e
	}
	if e = next.Chown(f.uid, f.gid); e != nil {
		return nil, e
	}
	if e = next.Chmod(0600); e != nil {
		return nil, e
	}
	if e = next.Sync(); e != nil {
		return nil, e
	}
	var current unix.Stat_t
	if e = unix.Fstatat(int(dir.Fd()), ".ftpquota", &current, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return nil, e
	}
	if current.Ino != st.Ino || current.Dev != st.Dev || current.Nlink != 1 {
		return nil, errors.New("FTP 容量计数在统计期间被替换，未覆盖")
	}
	if e = unix.Renameat(int(dir.Fd()), name, int(dir.Fd()), ".ftpquota"); e != nil {
		return nil, e
	}
	if e = dir.Sync(); e != nil {
		return nil, errors.New("FTP 完整计数已替换，但目录同步失败；未自动启动服务，请核对备份与计数")
	}
	return map[string]any{"ok": true, "username": username, "quota_usage_files": count, "quota_usage_bytes": size, "backup_id": backupID, "soft_quota": true, "shared_home_counter": true, "service_active": false}, nil
}
