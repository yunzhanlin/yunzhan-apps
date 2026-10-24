//go:build linux

package executor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const nfsServerUnit = "panel-nfs-server.service"
const nfsServerRun = "/run/panel-nfs-server"

type nfsExport struct {
	ID       string   `json:"id"`
	SiteID   string   `json:"site_id"`
	Path     string   `json:"path"`
	Clients  []string `json:"clients"`
	ReadOnly bool     `json:"read_only"`
	ExportID int      `json:"export_id"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Device   uint64   `json:"device"`
	Inode    uint64   `json:"inode"`
}
type nfsServerConfig struct {
	Revision         int64       `json:"revision"`
	BindAddress      string      `json:"bind_address"`
	Port             int         `json:"port"`
	ExposureApproved bool        `json:"exposure_approved"`
	Exports          []nfsExport `json:"exports"`
}
type nfsServerTransaction struct {
	ID         string            `json:"id"`
	State      string            `json:"state"`
	Old        []byte            `json:"old"`
	OldExists  bool              `json:"old_exists"`
	NextSHA    string            `json:"next_sha256"`
	WasActive  bool              `json:"was_active"`
	Time       string            `json:"time"`
	ApplyOwner *moduleApplyOwner `json:"apply_owner,omitempty"`
}

func defaultNFSServerConfig() nfsServerConfig {
	return nfsServerConfig{BindAddress: "127.0.0.1", Port: 2049, Exports: []nfsExport{}}
}
func nfsClientNetworks(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, errors.New("每个导出必须指定 1–16 个客户端 IP/CIDR，不能使用通配符或 DNS")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		var a netip.Addr
		var canonical string
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Bits() == 0 {
				return nil, errors.New("客户端 CIDR 格式无效，拒绝整个互联网的 /0 清单")
			}
			a, canonical = prefix.Addr(), prefix.Masked().String()
		} else {
			var err error
			a, err = netip.ParseAddr(value)
			if err != nil || a.IsUnspecified() {
				return nil, errors.New("客户端必须为明确 IP/CIDR")
			}
			canonical = a.String()
		}
		if a.IsMulticast() || a.Is4In6() || a.Zone() != "" || a.IsLinkLocalUnicast() || a == netip.MustParseAddr("255.255.255.255") {
			return nil, errors.New("客户端地址不支持组播、映射地址、接口区域或链路本地地址")
		}
		if !seen[canonical] {
			seen[canonical], out = true, append(out, canonical)
		}
	}
	return out, nil
}
func validateNFSServerConfig(v nfsServerConfig) error {
	a, err := netip.ParseAddr(v.BindAddress)
	if err != nil || a.Is4In6() || a.Zone() != "" || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.MustParseAddr("255.255.255.255") || v.Revision < 0 || v.Revision >= 1<<60 {
		return errors.New("NFS 服务配置身份或监听地址无效")
	}
	if !a.IsLoopback() && !v.ExposureApproved {
		return errors.New("非回环 NFS 监听须明确确认；AUTH_SYS 不加密，仅适合可信网络或 VPN")
	}
	if v.Port < 1024 || v.Port > 65535 || v.Port == 19100 || v.Port == 19101 || v.Port == 19102 || v.Port == 19080 || len(v.Exports) > 64 {
		return errors.New("NFS 端口须为 1024–65535，不能占用面板端口；最多 64 个导出")
	}
	ids, exports, paths := map[string]bool{}, map[int]bool{}, map[string]bool{}
	for _, e := range v.Exports {
		path := e.SiteID + "/" + e.Path
		clients, err := nfsClientNetworks(e.Clients)
		if err != nil || strings.Join(clients, ",") != strings.Join(e.Clients, ",") || !moduleResourceID.MatchString(e.ID) || !core.ValidID(e.SiteID) || !core.ValidFilePath(e.Path, true) || ids[e.ID] || exports[e.ExportID] || paths[path] || e.ExportID < 1 || e.ExportID > 65535 || e.UID <= 0 || e.GID <= 0 || e.Device == 0 || e.Inode == 0 {
			return errors.New("NFS 导出配置、目录身份或客户端清单无效，拒绝部分应用")
		}
		ids[e.ID], exports[e.ExportID], paths[path] = true, true, true
	}
	return nil
}
func (s *Service) nfsServerConfig() (nfsServerConfig, error) {
	v := defaultNFSServerConfig()
	b, err := ftpPrivateRead(filepath.Join(s.moduleDir("nfs-manager"), "server.json"), 128<<10)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	if err = decodeFTPPrivateJSON(b, &v); err != nil {
		return v, errors.New("NFS 服务清单损坏，拒绝覆盖")
	}
	return v, validateNFSServerConfig(v)
}
func (s *Service) lockNFSServer() (*os.File, error) {
	return s.lockNFSFile("server.lock")
}
func (s *Service) lockNFSFile(name string) (*os.File, error) {
	if name != "server.lock" && name != "clients.lock" && name != "client-helper.lock" {
		return nil, errors.New("NFS 私有锁名称无效")
	}
	dir := s.moduleDir("nfs-manager")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := ordinary(dir, true); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		if err == nil && (st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
			err = errors.New("NFS 私有锁身份无效")
		}
		if err == nil {
			err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		}
	}
	if err != nil {
		if f != nil {
			f.Close()
		}
		return nil, errors.New("NFS 配置正在修改或恢复，或私有锁权限异常")
	}
	return f, nil
}
func (s *Service) nfsPending() bool {
	return exists(filepath.Join(s.moduleDir("nfs-manager"), "pending-server.json"))
}
func (s *Service) finishNFSServerTransaction(t nfsServerTransaction) error {
	dir := s.moduleDir("nfs-manager")
	if err := moduleWrite(filepath.Join(dir, "pending-server.json"), t); err != nil {
		return err
	}
	if err := moduleWrite(filepath.Join(dir, "server-transactions", t.ID+".json"), t); err != nil {
		return err
	}
	return os.Remove(filepath.Join(dir, "pending-server.json"))
}
func (s *Service) recoverNFSServer() (bool, error) {
	dir := s.moduleDir("nfs-manager")
	b, err := ftpPrivateRead(filepath.Join(dir, "pending-server.json"), 256<<10)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var t nfsServerTransaction
	if decodeFTPPrivateJSON(b, &t) != nil || !core.ValidID(t.ID) || len(t.Old) > 128<<10 || len(t.NextSHA) != 64 || t.State != "applying" && t.State != "committed" && t.State != "recovered" {
		return false, errors.New("NFS 恢复记录损坏；保留原文件与记录")
	}
	if t.State != "applying" {
		return false, s.finishNFSServerTransaction(t)
	}
	path := filepath.Join(dir, "server.json")
	current, err := ftpPrivateRead(path, 128<<10)
	present := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if (!present && t.OldExists) || (present && core.Hash(string(current)) != t.NextSHA && (!t.OldExists || core.Hash(string(current)) != core.Hash(string(t.Old)))) {
		return false, errors.New("NFS 服务清单被外部修改，拒绝覆盖；恢复记录已保留")
	}
	if t.OldExists {
		var old nfsServerConfig
		if decodeFTPPrivateJSON(t.Old, &old) != nil || validateNFSServerConfig(old) != nil {
			return false, errors.New("NFS 恢复清单无效")
		}
		if err = atomicWrite(path, t.Old, 0600); err != nil {
			return false, err
		}
	} else if present {
		if err = os.Remove(path); err != nil {
			return false, err
		}
	}
	t.State = "recovered"
	return t.WasActive, s.finishNFSServerTransaction(t)
}
func RecoverNFSServer() error {
	s := New(Config{})
	if !s.moduleInstalled("nfs-manager") {
		return nil
	}
	lock, err := s.lockNFSServer()
	if err != nil {
		return err
	}
	defer lock.Close()
	_, err = s.recoverNFSServer()
	return err
}

// A descriptor rooted at the website pins the export's actual directory.
// Never hand an administrator-supplied absolute path to the NFS daemon.
func (s *Service) openNFSExport(e nfsExport, check bool) (*os.File, nfsExport, error) {
	f, err := s.openFiles(e.SiteID)
	if err != nil {
		return nil, e, err
	}
	defer f.Close()
	if f.uid <= 0 || f.gid <= 0 {
		return nil, e, errors.New("NFS 拒绝 root 所有的网站")
	}
	path := e.Path
	if path == "" {
		path = "."
	}
	fd, err := f.public.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, e, err
	}
	st, err := fd.Stat()
	if err != nil {
		fd.Close()
		return nil, e, err
	}
	identity := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || identity.Uid != uint32(f.uid) || identity.Gid != uint32(f.gid) || check && (e.UID != f.uid || e.GID != f.gid || e.Device != uint64(identity.Dev) || e.Inode != identity.Ino) {
		fd.Close()
		return nil, e, errors.New("NFS 目录已替换或归属改变；需先移除旧导出并重新登记，不静默导出新目录")
	}
	e.UID, e.GID, e.Device, e.Inode = f.uid, f.gid, uint64(identity.Dev), identity.Ino
	return fd, e, nil
}
func (s *Service) validateNFSExportPaths(v nfsServerConfig) error {
	for _, e := range v.Exports {
		f, _, err := s.openNFSExport(e, true)
		if err != nil {
			return fmt.Errorf("导出 %s：%w", e.ID, err)
		}
		f.Close()
	}
	return nil
}
func (s *Service) nfsActive(ctx context.Context) bool {
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", nfsServerUnit)
	return err == nil && strings.TrimSpace(state) == "active"
}
func (s *Service) restartNFSServer(ctx context.Context) error {
	// An explicit, validated apply or rollback must not be blocked by the
	// start-limit consumed by a failed candidate. Reset only our owned unit;
	// automatic crash restarts retain systemd's rate limiting.
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "reset-failed", nfsServerUnit); err != nil {
		return err
	}
	_, err := s.Config.Run(ctx, "/usr/bin/systemctl", "restart", nfsServerUnit)
	return err
}
func nfsRPCNull(ctx context.Context, address string) error {
	d := net.Dialer{Timeout: time.Second}
	f, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer f.Close()
	f.SetDeadline(time.Now().Add(2 * time.Second))
	// ONC RPC v2, NFS program 100003, NFSv4 NULL, AUTH_NONE.
	words := []uint32{0x80000028, 0x795a4e34, 0, 2, 100003, 4, 0, 0, 0, 0, 0}
	request := make([]byte, 4*len(words))
	for i, w := range words {
		binary.BigEndian.PutUint32(request[i*4:], w)
	}
	if _, err = io.Copy(f, strings.NewReader(string(request))); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(f, head); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(head)
	if size&0x80000000 == 0 || size&0x7fffffff < 24 || size&0x7fffffff > 1024 {
		return errors.New("NFS RPC 回复长度无效")
	}
	data := make([]byte, size&0x7fffffff)
	if _, err = io.ReadFull(f, data); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(data[:4]) != words[1] || binary.BigEndian.Uint32(data[4:8]) != 1 || binary.BigEndian.Uint32(data[8:12]) != 0 {
		return errors.New("NFSv4 NULL 调用未被接受")
	}
	verifier := int(binary.BigEndian.Uint32(data[16:20]))
	offset := 20 + (verifier+3)/4*4
	if verifier > 400 || offset+4 != len(data) || binary.BigEndian.Uint32(data[offset:]) != 0 {
		return errors.New("NFS RPC 身份或成功回复无效")
	}
	return nil
}
func (s *Service) probeNFSServer(ctx context.Context, v nfsServerConfig) error {
	if s.Config.SystemRoot != "/" {
		_, err := s.Config.Run(ctx, "nfs-rpc-null", v.BindAddress, strconv.Itoa(v.Port))
		return err
	}
	address := v.BindAddress
	if a, _ := netip.ParseAddr(address); a.IsUnspecified() {
		address = "127.0.0.1"
		if a.Is6() {
			address = "::1"
		}
	}
	var last error
	runtime, err := s.nfsRuntime()
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 15; attempt++ {
		if !s.nfsActive(ctx) {
			last = errors.New("受管 NFS 服务未运行")
		} else {
			pidText, e := s.Config.Run(ctx, "/usr/bin/systemctl", "show", nfsServerUnit, "--property=MainPID", "--value")
			pid, parseErr := strconv.Atoi(strings.TrimSpace(pidText))
			exe, readErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
			if e != nil || parseErr != nil || pid <= 1 || readErr != nil || exe != runtime.Binary {
				last = errors.New("NFS 服务尚未运行已核对的原生程序")
			} else {
				last = nfsRPCNull(ctx, net.JoinHostPort(address, strconv.Itoa(v.Port)))
			}
		}
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("实际 NFSv4 RPC 检查失败：%w", last)
}
func jsonMarshalNFSConfig(v nfsServerConfig) ([]byte, error) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}
func (s *Service) applyNFSServer(ctx context.Context, v nfsServerConfig) error {
	if err := validateNFSServerConfig(v); err != nil {
		return err
	}
	if err := s.validateNFSExportPaths(v); err != nil {
		return err
	}
	dir := s.moduleDir("nfs-manager")
	backups, err := filepath.Glob(filepath.Join(dir, "server-transactions", "*.json"))
	if err != nil || len(backups) >= 512 {
		return errors.New("NFS 恢复备份达到 512 条，请先安全归档；不自动删除")
	}
	path := filepath.Join(dir, "server.json")
	old, err := ftpPrivateRead(path, 128<<10)
	present := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next, err := jsonMarshalNFSConfig(v)
	if err != nil {
		return err
	}
	owner, err := currentModuleApplyOwner()
	if err != nil {
		return err
	}
	if s.Config.SystemRoot == "/" {
		if err = s.authorizeModuleCandidate(ctx, filepath.Join(dir, "server.lock"), owner); err != nil {
			return err
		}
	}
	t := nfsServerTransaction{ID: core.ID(), State: "applying", Old: old, OldExists: present, NextSHA: core.Hash(string(next)), WasActive: s.nfsActive(ctx), Time: core.Now(), ApplyOwner: owner}
	if err = moduleWrite(filepath.Join(dir, "pending-server.json"), t); err != nil {
		return err
	}
	rollback := func(cause error) error {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		active, re := s.recoverNFSServer()
		if re != nil {
			return fmt.Errorf("%w；恢复失败，私有记录保留：%v", cause, re)
		}
		if active {
			if re = s.restartNFSServer(recoveryCtx); re != nil {
				return fmt.Errorf("%w；旧 NFS 服务重新启动失败：%v", cause, re)
			}
			previous, re := s.nfsServerConfig()
			if re == nil {
				re = s.probeNFSServer(recoveryCtx, previous)
			}
			if re != nil {
				return fmt.Errorf("%w；旧服务真实检查失败：%v", cause, re)
			}
		}
		return cause
	}
	if err = atomicWrite(path, next, 0600); err != nil {
		return rollback(err)
	}
	if t.WasActive {
		if err = s.restartNFSServer(ctx); err != nil {
			return rollback(err)
		}
		if err = s.probeNFSServer(ctx, v); err != nil {
			return rollback(err)
		}
	}
	t.State = "committed"
	return s.finishNFSServerTransaction(t)
}

func (s *Service) moduleNFSServer(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if action == "server-start" || action == "server-config" || action == "export-save" || action == "export-remove" {
		if s.nfsPending() {
			return nil, errors.New("NFS 有未完成事务，请先恢复")
		}
		if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "panel-nfs-server-recover.service"); err != nil {
			return nil, err
		}
	}
	lock, err := s.lockNFSServer()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if action == "server-recover" {
		active, err := s.recoverNFSServer()
		if err != nil {
			return nil, err
		}
		enabled, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-enabled", nfsServerUnit)
		if active && strings.TrimSpace(enabled) == "enabled" {
			if err = s.restartNFSServer(ctx); err != nil {
				return nil, err
			}
			previous, e := s.nfsServerConfig()
			if e != nil {
				return nil, e
			}
			if e = s.probeNFSServer(ctx, previous); e != nil {
				return nil, e
			}
		}
		return map[string]any{"recovered": true}, nil
	}
	v, err := s.nfsServerConfig()
	if err != nil {
		return nil, err
	}
	if action == "server-report" {
		_, runtimeErr := s.nfsRuntime()
		enabled, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-enabled", nfsServerUnit)
		out := map[string]any{"config": v, "service_active": s.nfsActive(ctx), "boot_enabled": strings.TrimSpace(enabled) == "enabled", "recovery_pending": s.nfsPending(), "runtime_ready": runtimeErr == nil, "encrypted": false, "client_identity": "all_squash to website UID/GID", "firewall_changed": false}
		if runtimeErr != nil {
			out["runtime_error"] = runtimeErr.Error()
		}
		if err := s.validateNFSExportPaths(v); err != nil {
			out["export_error"] = err.Error()
		}
		return out, nil
	}
	if action == "server-stop" {
		_, err = s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", nfsServerUnit)
		return map[string]any{"service_active": false, "exports_and_files_retained": true}, err
	}
	if s.nfsPending() {
		return nil, errors.New("NFS 有未完成事务，请先恢复")
	}
	if action == "server-start" || action == "server-probe" {
		if _, err = s.nfsRuntime(); err != nil {
			return nil, err
		}
		if err = s.validateNFSExportPaths(v); err != nil {
			return nil, err
		}
		if len(v.Exports) == 0 {
			return nil, errors.New("请先登记至少一个导出；不启动空服务")
		}
		if action == "server-start" {
			wasActive := s.nfsActive(ctx)
			if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "reset-failed", nfsServerUnit); err != nil {
				return nil, err
			}
			if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "start", nfsServerUnit); err != nil {
				return nil, err
			}
			if err = s.probeNFSServer(ctx, v); err != nil {
				if !wasActive {
					_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "stop", nfsServerUnit)
				}
				return nil, err
			}
			if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", nfsServerUnit); err != nil {
				return nil, err
			}
		}
		err = s.probeNFSServer(ctx, v)
		return map[string]any{"actual_nfs_v4_rpc": err == nil, "exports": len(v.Exports), "encrypted": false}, err
	}
	if in.ExpectedRevision != v.Revision {
		return nil, errors.New("NFS 服务修订号冲突，请刷新")
	}
	if action == "server-config" {
		v.BindAddress, v.Port = in.BindAddress, in.Port
		a, err := netip.ParseAddr(v.BindAddress)
		if err != nil {
			return nil, errors.New("NFS 监听地址无效")
		}
		if !a.IsLoopback() && in.Confirm != "EXPOSE NFS "+net.JoinHostPort(v.BindAddress, strconv.Itoa(v.Port)) {
			return nil, errors.New("非回环监听需要填写 EXPOSE NFS IP:端口；AUTH_SYS 未加密，不适合公开互联网")
		}
		if !a.IsUnspecified() && !a.IsLoopback() && s.Config.SystemRoot == "/" {
			addresses, err := net.InterfaceAddrs()
			if err != nil {
				return nil, err
			}
			local := false
			for _, address := range addresses {
				prefix, parseErr := netip.ParsePrefix(address.String())
				if parseErr == nil && prefix.Addr() == a {
					local = true
				}
			}
			if !local {
				return nil, errors.New("监听 IP 不属于本机接口")
			}
		}
		v.ExposureApproved = !a.IsLoopback()
	} else if action == "export-save" || action == "export-remove" {
		if !moduleResourceID.MatchString(in.ResourceID) {
			return nil, errors.New("导出名称需为 3–32 位小写标识")
		}
		found := -1
		for i, e := range v.Exports {
			if e.ID == in.ResourceID {
				found = i
			}
		}
		if action == "export-remove" {
			if found < 0 {
				return nil, errors.New("导出不存在")
			}
			if len(v.Exports) == 1 && s.nfsActive(ctx) {
				return nil, errors.New("先停止 NFS 服务，再移除最后一个导出；不会自动中断所有共享")
			}
			v.Exports = append(v.Exports[:found], v.Exports[found+1:]...)
		} else {
			if !core.ValidID(in.SiteID) || !core.ValidFilePath(in.Path, true) {
				return nil, errors.New("请选择受管网站内的普通目录")
			}
			if !in.ReadOnly && in.Confirm != "SHARE RW "+in.ResourceID {
				return nil, errors.New("可写导出允许客户端修改该网站，需填写 SHARE RW 导出名称")
			}
			clients, err := nfsClientNetworks(in.ClientAllow)
			if err != nil {
				return nil, err
			}
			e := nfsExport{ID: in.ResourceID, SiteID: in.SiteID, Path: in.Path, Clients: clients, ReadOnly: in.ReadOnly}
			if found >= 0 {
				old := v.Exports[found]
				if old.SiteID != e.SiteID || old.Path != e.Path {
					return nil, errors.New("现有导出不能静默切换目录；先移除再建立新导出")
				}
				e = old
				e.Clients, e.ReadOnly = clients, in.ReadOnly
			} else {
				used := map[int]bool{}
				for _, saved := range v.Exports {
					used[saved.ExportID] = true
				}
				for e.ExportID = 1; used[e.ExportID]; e.ExportID++ {
				}
				if err = s.ensureModuleSiteIdentity(ctx, e.SiteID); err != nil {
					return nil, err
				}
			}
			fd, e, err := s.openNFSExport(e, found >= 0)
			if err != nil {
				return nil, err
			}
			fd.Close()
			if found >= 0 {
				v.Exports[found] = e
			} else {
				v.Exports = append(v.Exports, e)
			}
		}
	} else {
		return nil, errors.New("NFS 服务端操作无效")
	}
	v.Revision++
	sort.Slice(v.Exports, func(i, j int) bool { return v.Exports[i].ID < v.Exports[j].ID })
	if err = s.applyNFSServer(ctx, v); err != nil {
		return nil, err
	}
	return map[string]any{"config": v, "service_active": s.nfsActive(ctx), "firewall_changed": false}, nil
}

func renderNFSServer(v nfsServerConfig, plugins string) (string, error) {
	if err := validateNFSServerConfig(v); err != nil {
		return "", err
	}
	if !strings.HasPrefix(plugins, appNativeRoot+"/nfs-manager/") || strings.ContainsAny(plugins, "\"\n\r\x00") || strings.Contains(plugins, "..") {
		return "", errors.New("NFS 固定插件路径无效")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "NFS_CORE_PARAM { Bind_addr = %s; NFS_Port = %d; Protocols = 4; Enable_UDP = false; Enable_NLM = false; Enable_RQUOTA = false; Plugins_Dir = \"%s\"; RPC_Max_Connections = 128; RPC_Ioq_ThrdMax = 32; Dbus_Name_Prefix = cloudstack; }\nNFS_KRB5 { Active_krb5 = false; }\n", v.BindAddress, v.Port, plugins)
	b.WriteString("NFSv4 { RecoveryBackend = fs; RecoveryRoot = /var/lib/panel-executor/nfs-server-recovery; Lease_Lifetime = 30; Grace_Period = 30; Max_Client_Ids = 128; Minor_Versions = 1,2; }\nMDCACHE { Entries_HWMark = 4096; }\nLOG { Default_Log_Level = WARN; }\n")
	for _, e := range v.Exports {
		access := "RO"
		if !e.ReadOnly {
			access = "RW"
		}
		fmt.Fprintf(&b, "EXPORT { Export_Id = %d; Path = \"%s/exports/%s\"; Pseudo = /%s; Access_Type = None; Squash = all_squash; Anonymous_uid = %d; Anonymous_gid = %d; SecType = sys; Protocols = 4; Transports = TCP; PrivilegedPort = true; MaxRead = 1048576; MaxWrite = 1048576; CLIENT { Clients = %s; Access_Type = %s; } FSAL { Name = VFS; } }\n", e.ExportID, nfsServerRun, e.ID, e.ID, e.UID, e.GID, strings.Join(e.Clients, ", "), access)
	}
	return b.String(), nil
}

func (s *Service) authorizeNFSStart(ctx context.Context) error {
	dir := s.moduleDir("nfs-manager")
	b, err := ftpPrivateRead(filepath.Join(dir, "pending-server.json"), 256<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var t nfsServerTransaction
	if decodeFTPPrivateJSON(b, &t) != nil || !core.ValidID(t.ID) || t.State != "applying" || !t.WasActive || len(t.NextSHA) != 64 {
		return errors.New("NFS 未完成事务不能用于启动，必须先恢复")
	}
	current, err := ftpPrivateRead(filepath.Join(dir, "server.json"), 128<<10)
	if err != nil || core.Hash(string(current)) != t.NextSHA {
		return errors.New("NFS 候选清单不完整或被外部修改，拒绝启动")
	}
	return s.authorizeModuleCandidate(ctx, filepath.Join(dir, "server.lock"), t.ApplyOwner)
}
func requireNFSIdentityCapabilities(stage string) error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var capabilities [2]unix.CapUserData
	if err := unix.Capget(&header, &capabilities[0]); err != nil {
		return err
	}
	const mask = 1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID | 1<<unix.CAP_DAC_READ_SEARCH
	if capabilities[0].Effective&mask != mask {
		return fmt.Errorf("NFS VFS %s 缺少网站用户切换或文件句柄权限（有效权限 %#x），拒绝以错误身份提供共享", stage, capabilities[0].Effective)
	}
	return nil
}

func ServeNFSServer() error {
	// Capability changes are per kernel thread, not per Go goroutine. Keep
	// preparation, final privilege reduction and exec on exactly one thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := requireNFSIdentityCapabilities("启动时"); err != nil {
		return err
	}
	s := New(Config{SitesDir: "/srv/panel/sites"})
	if !s.moduleInstalled("nfs-manager") {
		return errors.New("NFS 模块未安装")
	}
	if err := s.authorizeNFSStart(context.Background()); err != nil {
		return err
	}
	self, err := os.Stat("/proc/self/ns/mnt")
	if err != nil {
		return err
	}
	initial, err := os.Stat("/proc/1/ns/mnt")
	if err != nil {
		return err
	}
	if os.SameFile(self, initial) {
		return errors.New("NFS 服务必须运行于独立 systemd 挂载命名空间，拒绝修改主机挂载")
	}
	if err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err = detachInheritedNFSClients(); err != nil {
		return fmt.Errorf("隔离继承的 NFS 客户端失败：%w", err)
	}
	if err = protectNFSPrivateTemporaryAndHomePaths(); err != nil {
		return err
	}
	v, err := s.nfsServerConfig()
	if err != nil {
		return err
	}
	if len(v.Exports) == 0 {
		return errors.New("NFS 没有导出，拒绝启动")
	}
	runtime, err := s.nfsRuntime()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(nfsServerRun, "exports"), 0700); err != nil {
		return err
	}
	if err = ownedRuntimePath(nfsServerRun, true); err != nil {
		return err
	}
	for _, e := range v.Exports {
		fd, _, err := s.openNFSExport(e, true)
		if err != nil {
			return err
		}
		if _, _, err = unix.NameToHandleAt(int(fd.Fd()), "", unix.AT_EMPTY_PATH); err != nil {
			fd.Close()
			return fmt.Errorf("导出 %s 的文件系统不支持受管 VFS 文件句柄：%w", e.ID, err)
		}
		target := filepath.Join(nfsServerRun, "exports", e.ID)
		if err = os.Mkdir(target, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			fd.Close()
			return err
		}
		if err = ownedRuntimePath(target, true); err != nil {
			fd.Close()
			return err
		}
		// The service has a private mount namespace. These aliases disappear
		// with it and cannot change any host mount or recursively expose a child.
		err = unix.Mount(fmt.Sprintf("/proc/self/fd/%d", fd.Fd()), target, "", unix.MS_BIND, "")
		fd.Close()
		if err != nil {
			return err
		}
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
		if e.ReadOnly {
			flags |= unix.MS_RDONLY
		}
		if err = unix.Mount("", target, "", flags, ""); err != nil {
			return err
		}
	}
	text, err := renderNFSServer(v, runtime.LibraryDir)
	if err != nil {
		return err
	}
	configuration := filepath.Join(nfsServerRun, "ganesha.conf")
	if err = atomicWrite(configuration, []byte(text), 0600); err != nil {
		return err
	}
	if err = os.MkdirAll("/var/lib/panel-executor/nfs-server-recovery", 0700); err != nil {
		return err
	}
	if err = s.authorizeNFSStart(context.Background()); err != nil {
		return err
	}
	if err = requireNFSIdentityCapabilities("执行前"); err != nil {
		return err
	}
	if err = restrictNFSDaemonCapabilities(); err != nil {
		return fmt.Errorf("NFS 守护进程权限收紧失败：%w", err)
	}
	// Only fixed, root-owned and hash-checked libraries enter the environment.
	return syscall.Exec(runtime.Binary, []string{runtime.Binary, "-F", "-f", configuration, "-p", filepath.Join(nfsServerRun, "server.pid"), "-L", "STDOUT"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LD_LIBRARY_PATH=" + runtime.LibraryDir, "LD_PRELOAD=" + runtime.Shim})
}

// Ganesha 6 needs SYS_RESOURCE for PR_SET_IO_FLUSHER at startup and drops it
// itself before serving requests. Do not disable that deadlock protection.
var nfsBootstrapOnlyCapabilities = [...]uint{unix.CAP_SYS_ADMIN, unix.CAP_SYS_PTRACE, unix.CAP_SETPCAP}

func nfsDaemonCapabilities(data [2]unix.CapUserData) [2]unix.CapUserData {
	for _, capability := range nfsBootstrapOnlyCapabilities {
		word, bit := capability/32, uint32(1)<<(capability%32)
		data[word].Effective &^= bit
		data[word].Permitted &^= bit
		data[word].Inheritable &^= bit
	}
	return data
}

func restrictNFSDaemonCapabilities() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	// Drop the bounding set while SETPCAP is still held. It is last in this
	// list; removing a bounding capability does not remove its effective bit.
	for _, capability := range nfsBootstrapOnlyCapabilities {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil {
			return err
		}
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_LOWER, uintptr(capability), 0, 0); err != nil {
			return err
		}
	}
	data = nfsDaemonCapabilities(data)
	if err := unix.Capset(&header, &data[0]); err != nil {
		return err
	}
	return requireNFSIdentityCapabilities("权限收紧后")
}

// The caller has proved that this is not PID 1's mount namespace and made
// every mount recursively private. A cloned local NFS client must not survive
// inside the server: on exit its DESTROY_SESSION can wait on the stopped
// daemon itself, even after the host has unmounted that client. Detach only
// these private copies, never the host's mount or a forced host unmount.
func inheritedNFSClientPaths(data string) ([]string, error) {
	var paths []string
	for _, line := range strings.Split(data, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		filesystem := strings.Fields(right)
		if !ok || len(filesystem) == 0 || filesystem[0] != "nfs" && filesystem[0] != "nfs4" {
			continue
		}
		fields := strings.Fields(left)
		if len(fields) < 6 {
			return nil, errors.New("NFS 挂载表损坏")
		}
		path := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(fields[4])
		if path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\n\r") {
			return nil, errors.New("不支持隔离根目录或异常 NFS 挂载点")
		}
		paths = append(paths, path)
		if len(paths) > 256 {
			return nil, errors.New("继承 NFS 挂载超过安全上限")
		}
	}
	sort.SliceStable(paths, func(i, j int) bool { return strings.Count(paths[i], "/") > strings.Count(paths[j], "/") })
	return paths, nil
}

func detachInheritedNFSClients() error {
	read := func() ([]string, error) {
		data, err := readModuleProcFile("/proc/self/mountinfo", 1<<20)
		if err != nil {
			return nil, err
		}
		return inheritedNFSClientPaths(string(data))
	}
	paths, err := read()
	if err != nil {
		return err
	}
	for _, path := range paths {
		// statfs on an NFS directory performs a remote RPC, which could wait
		// on the daemon we have not started yet. O_PATH + kernel fdinfo proves
		// the visible mount identity without performing an NFS FSSTAT call.
		fd, openErr := os.OpenFile(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		fdinfo, readErr := readModuleProcFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd.Fd()), 4096)
		fd.Close()
		if readErr != nil {
			return readErr
		}
		mountID := ""
		for _, line := range strings.Split(string(fdinfo), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "mnt_id:" {
				mountID = fields[1]
			}
		}
		data, readErr := readModuleProcFile("/proc/self/mountinfo", 1<<20)
		if readErr != nil {
			return readErr
		}
		visibleNFS := false
		for _, line := range strings.Split(string(data), "\n") {
			left, right, ok := strings.Cut(line, " - ")
			fields, filesystem := strings.Fields(left), strings.Fields(right)
			if ok && len(fields) >= 6 && len(filesystem) >= 1 && mountID != "" && fields[0] == mountID && (filesystem[0] == "nfs" || filesystem[0] == "nfs4") {
				visibleNFS = true
			}
		}
		if !visibleNFS {
			return fmt.Errorf("NFS 挂载 %s 被其他挂载遮挡，拒绝删除不明挂载", path)
		}
		if err = unix.Unmount(path, unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW); err != nil {
			return err
		}
	}
	remaining, err := read()
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return errors.New("独立 NFS 服务仍继承客户端挂载，拒绝启动")
	}
	return nil
}

func protectNFSPrivateTemporaryAndHomePaths() error {
	for _, entry := range []struct{ path, options string }{
		{"/tmp", "mode=1777,size=16m"}, {"/var/tmp", "mode=1777,size=16m"},
		{"/root", "mode=000,size=1m"}, {"/home", "mode=000,size=1m"}, {"/run/user", "mode=000,size=1m"},
	} {
		info, err := os.Lstat(entry.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("NFS 隔离路径 %s 必须是普通目录", entry.path)
		}
		flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
		if entry.path != "/tmp" && entry.path != "/var/tmp" {
			flags |= unix.MS_RDONLY
		}
		if err = unix.Mount("tmpfs", entry.path, "tmpfs", flags, entry.options); err != nil {
			return err
		}
	}
	return nil
}
