//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const remoteSyncScope = "单向 SFTP 增量复制；不删除远端额外文件、不执行 SSH 命令。固定 IP 和主机公钥；密码或私钥仅本机加密保存。远端必须为可信 Linux/OpenSSH、受限非 root SFTP 账户，目标与私有备份目录由该账户拥有且同一文件系统；路径不接受符号链接。修改受管文件前保留原文件，更新有短暂路径交接，不保证零停机。每次最多 10000 文件、256 MiB，单文件 8 MiB、120 秒；128 个活动任务，可按完整记录摘要归档终态任务到本机私有目录，最多 2048 份或 16 MiB；归档不释放原任务身份，不重新执行。远端最多 512 份事务及 256 MiB 备份，不自动删除证据。支持手动排队或显式启用的定时补查，间隔 60–86400 秒；最多保留 16 个计划，每个连接一个未移除计划，完整成功后再安排下一次，错过多次只合并一次。接受中断、冲突、凭据改变或持久化失败安全暂停，保留原任务标识，不盲目重传；暂停阻止后续交接，移除保留身份与证据。可显式开启 Linux 内核事件，0.5–2 秒合并后持久保存变化序号，由 5 秒任务队列接收；首次监听、重启及目录变化补查。任务执行期间的新变化不由旧任务确认；监听超限或不可用显示降级并保留定时补查，队列或备份满额安全暂停。"

type remoteSyncConfig struct {
	ID       string                `json:"id"`
	Target   core.RemoteSyncTarget `json:"remote_target"`
	Revision int64                 `json:"revision"`
	Enabled  bool                  `json:"enabled"`
	Cipher   []byte                `json:"cipher"`
	AuthKind string                `json:"auth_kind"`
	SpecSHA  string                `json:"spec_sha256"`
}

func validRemotePath(p string) bool {
	if len(p) > 512 || !strings.HasPrefix(p, "/") || p == "/" || path.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n\\") {
		return false
	}
	for _, prefix := range []string{"/etc", "/proc", "/sys", "/dev", "/root", "/bin", "/sbin", "/usr", "/boot", "/run"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return false
		}
	}
	return true
}

var remoteSyncUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validateRemoteTarget(t core.RemoteSyncTarget) error {
	ip, err := netip.ParseAddr(t.Address)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || ip.String() != t.Address || t.Port < 1 || t.Port > 65535 || !remoteSyncUsername.MatchString(t.Username) || t.Username == "root" || !validRemotePath(t.Root) || !validRemotePath(t.BackupRoot) {
		return errors.New("SFTP 需要规范的固定 IP、有效端口、非 root 用户及明确的普通绝对目录")
	}
	if t.Root == t.BackupRoot || strings.HasPrefix(t.Root, t.BackupRoot+"/") || strings.HasPrefix(t.BackupRoot, t.Root+"/") {
		return errors.New("远端私有备份必须在目标目录之外，且两者不能互相包含")
	}
	if len(t.HostKey) > 2048 {
		return errors.New("SSH 主机公钥过长")
	}
	key, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if err != nil || len(opts) != 0 || len(bytes.TrimSpace(rest)) != 0 || strings.HasPrefix(key.Type(), "ssh-dss") || strings.Contains(key.Type(), "cert-") {
		return errors.New("必须提供已独立核实的单个 SSH 主机公钥；不接受公钥证书、选项或自动信任")
	}
	return nil
}

func remoteSpecSHA(t core.RemoteSyncTarget) string {
	b, _ := json.Marshal(t)
	return core.Hash(string(b))
}
func (s *Service) remoteSyncDir() string { return filepath.Join(s.moduleDir("files-sync"), "remote") }
func (s *Service) remoteConfigPath(id string) string {
	return filepath.Join(s.remoteSyncDir(), "targets", id+".json")
}

// Local secrets and journals are owned by the executor, never the site user.
func remotePrivateFile(p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || v.Nlink != 1 || v.Uid != uint32(os.Geteuid()) {
		return errors.New("远端同步私有记录权限或身份无效")
	}
	return nil
}
func remoteRead(p string, out any) error {
	if err := remotePrivateFile(p); err != nil {
		return err
	}
	parent := filepath.Dir(p)
	found := false
	for depth := 0; depth < 4; depth++ {
		st, e := os.Lstat(parent)
		if e != nil {
			return e
		}
		a, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || st.Mode().Perm() != 0700 || !ok || a.Uid != uint32(os.Geteuid()) {
			return errors.New("远端同步私有记录父目录权限或身份无效")
		}
		if filepath.Base(parent) == "remote" {
			found = true
			break
		}
		parent = filepath.Dir(parent)
	}
	if !found {
		return errors.New("远端私有记录不在固定命名空间")
	}
	f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	a, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ok || a.Nlink != 1 || a.Uid != uint32(os.Geteuid()) {
		return errors.New("远端同步私有记录打开后身份改变")
	}
	b, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if e != nil {
		return e
	}
	if len(b) > 4<<20 {
		return errors.New("远端同步私有记录超过 4 MiB")
	}
	if e = json.Unmarshal(b, out); e != nil {
		return e
	}
	if job, ok := out.(*remoteSyncJob); ok {
		job.RecordSHA = core.Hash(string(b))
	}
	return nil
}
func (s *Service) remoteKey() ([]byte, error) {
	dir := s.remoteSyncDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("远端同步私有目录无效")
	}
	if a, ok := st.Sys().(*syscall.Stat_t); !ok || a.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("远端同步私有目录所有者无效")
	}
	p := filepath.Join(dir, "credential-key")
	if err = remotePrivateFile(p); errors.Is(err, os.ErrNotExist) {
		entries, er := os.ReadDir(filepath.Join(dir, "targets"))
		if er != nil && !errors.Is(er, os.ErrNotExist) {
			return nil, er
		}
		if len(entries) != 0 {
			return nil, errors.New("远端认证主密钥丢失，请恢复原密钥，不会生成替代密钥")
		}
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, er := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if er != nil {
			return nil, er
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, errors.New("远端认证主密钥持久化失败，未保存连接")
		}
		directory, er := os.Open(dir)
		if er != nil {
			return nil, er
		}
		er = directory.Sync()
		directory.Close()
		if er != nil {
			return nil, errors.New("远端认证主密钥目录持久化失败，未保存连接")
		}
	} else if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return nil, errors.New("远端认证主密钥损坏")
	}
	return key, nil
}
func (s *Service) remoteAEAD() (cipher.AEAD, error) {
	key, err := s.remoteKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func remoteAuthAAD(c remoteSyncConfig) []byte {
	return []byte("yunzhan-sftp-v1/" + c.ID + "/" + c.SpecSHA + "/" + c.AuthKind)
}
func (s *Service) sealRemoteAuth(c remoteSyncConfig, secret []byte) ([]byte, error) {
	a, err := s.remoteAEAD()
	if err != nil {
		return nil, err
	}
	n := make([]byte, a.NonceSize())
	if _, err = rand.Read(n); err != nil {
		return nil, err
	}
	return a.Seal(n, n, secret, remoteAuthAAD(c)), nil
}
func (s *Service) openRemoteAuth(c remoteSyncConfig) ([]byte, error) {
	a, err := s.remoteAEAD()
	if err != nil {
		return nil, err
	}
	if len(c.Cipher) <= a.NonceSize() || len(c.Cipher) > 65536 {
		return nil, errors.New("SFTP 认证记录损坏")
	}
	b, err := a.Open(nil, c.Cipher[:a.NonceSize()], c.Cipher[a.NonceSize():], remoteAuthAAD(c))
	if err != nil {
		return nil, errors.New("SFTP 认证记录无法解密，请恢复原密钥和连接记录")
	}
	return b, nil
}
func (s *Service) readRemoteConfig(id string) (remoteSyncConfig, error) {
	var c remoteSyncConfig
	if !syncPlanID.MatchString(id) {
		return c, errors.New("远端连接标识无效")
	}
	if err := remoteRead(s.remoteConfigPath(id), &c); err != nil {
		return c, err
	}
	if c.ID != id || c.Revision < 1 || c.SpecSHA != remoteSpecSHA(c.Target) || (c.AuthKind != "password" && c.AuthKind != "private-key") || len(c.Cipher) == 0 {
		return c, errors.New("远端连接记录身份无效")
	}
	return c, validateRemoteTarget(c.Target)
}
func remotePublicConfig(c remoteSyncConfig) map[string]any {
	key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(c.Target.HostKey))
	return map[string]any{"id": c.ID, "remote_target_id": c.ID, "remote_target": c.Target, "revision": c.Revision, "enabled": c.Enabled, "auth_kind": c.AuthKind, "host_key_fingerprint": ssh.FingerprintSHA256(key)}
}

type remoteSyncConnection struct {
	client  *remoteSyncClient
	ssh     *ssh.Client
	session *ssh.Session
	raw     net.Conn
	stop    func() bool
}

func (c *remoteSyncConnection) Close() {
	if c.stop != nil {
		c.stop()
	}
	c.raw.Close()
	c.session.Close()
	c.ssh.Close()
	c.client.Close()
}

// The upstream ReadDir accumulates all entries. Bound decrypted SFTP input
// while enumerating private directories, before an oversized listing can
// become an unbounded result slice. Total transfer traffic is bounded too.
type remoteSyncReader struct {
	io.Reader
	raw      net.Conn
	mu       sync.Mutex
	total    int64
	metadata int64
	listing  bool
}

func (r *remoteSyncReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.mu.Lock()
	r.total -= int64(n)
	if r.listing {
		r.metadata -= int64(n)
	}
	exceeded := r.total < 0 || r.listing && r.metadata < 0
	r.mu.Unlock()
	if exceeded {
		r.raw.Close()
		return n, errors.New("SFTP 输入超过受限传输或目录元数据预算")
	}
	return n, e
}

type remoteSyncClient struct {
	*sftp.Client
	reader *remoteSyncReader
}

func (c *remoteSyncClient) ReadDir(p string) ([]os.FileInfo, error) {
	c.reader.mu.Lock()
	c.reader.listing = true
	c.reader.metadata = 2 << 20
	c.reader.mu.Unlock()
	defer func() { c.reader.mu.Lock(); c.reader.listing = false; c.reader.mu.Unlock() }()
	entries, e := c.Client.ReadDir(p)
	if e != nil {
		return nil, errors.New("远端目录枚举失败或超过 2 MiB 元数据预算")
	}
	if len(entries) > 512 {
		return nil, errors.New("远端目录超过 512 个条目，拒绝不完整结果")
	}
	return entries, nil
}

func (s *Service) dialRemoteSync(ctx context.Context, c remoteSyncConfig) (*remoteSyncConnection, error) {
	if err := validateRemoteTarget(c.Target); err != nil {
		return nil, err
	}
	secret, err := s.openRemoteAuth(c)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	auth := ssh.Password(string(secret))
	if c.AuthKind == "private-key" {
		signer, err := ssh.ParsePrivateKey(secret)
		if err != nil {
			return nil, errors.New("SFTP 私钥不可解析或需要口令")
		}
		auth = ssh.PublicKeys(signer)
	}
	key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(c.Target.HostKey))
	cfg := &ssh.ClientConfig{User: c.Target.Username, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: func(_ string, _ net.Addr, actual ssh.PublicKey) error {
		if !bytes.Equal(key.Marshal(), actual.Marshal()) {
			return errors.New("固定 SSH 主机公钥不匹配")
		}
		return nil
	}, Timeout: 5 * time.Second}
	address := net.JoinHostPort(c.Target.Address, stringPort(c.Target.Port))
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("SFTP 固定地址无法连接")
	}
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	conn, channels, requests, err := ssh.NewClientConn(raw, address, cfg)
	if err != nil {
		stop()
		raw.Close()
		return nil, errors.New("SFTP SSH 认证或固定主机公钥验证失败")
	}
	raw.SetDeadline(time.Time{})
	client := ssh.NewClient(conn, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		stop()
		raw.Close()
		client.Close()
		return nil, errors.New("SFTP 会话不能创建")
	}
	output, err := session.StdoutPipe()
	if err != nil {
		stop()
		raw.Close()
		session.Close()
		client.Close()
		return nil, errors.New("SFTP 只读输出通道不能创建")
	}
	input, err := session.StdinPipe()
	if err != nil {
		stop()
		raw.Close()
		session.Close()
		client.Close()
		return nil, errors.New("SFTP 输入通道不能创建")
	}
	if err = session.RequestSubsystem("sftp"); err != nil {
		stop()
		raw.Close()
		session.Close()
		client.Close()
		return nil, errors.New("SFTP 子系统不可用；不会执行远端命令")
	}
	reader := &remoteSyncReader{Reader: output, raw: raw, total: 2 << 30}
	ft, err := sftp.NewClientPipe(reader, input, sftp.MaxConcurrentRequestsPerFile(2), sftp.UseConcurrentReads(false), sftp.UseConcurrentWrites(false))
	if err != nil {
		stop()
		raw.Close()
		client.Close()
		session.Close()
		return nil, errors.New("SFTP 子系统不可用；不会执行远端命令")
	}
	result := &remoteSyncConnection{client: &remoteSyncClient{ft, reader}, ssh: client, session: session, raw: raw, stop: stop}
	for _, extension := range []string{"hardlink@openssh.com", "fsync@openssh.com"} {
		if version, ok := ft.HasExtension(extension); !ok || version != "1" {
			result.Close()
			return nil, errors.New("SFTP 必须支持 OpenSSH 无覆盖硬链接与持久刷盘扩展")
		}
	}
	return result, nil
}

func remoteDirCheck(c *remoteSyncClient, p string, owner *uint32, private bool) error {
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		current = path.Join(current, part)
		st, err := c.Lstat(current)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("远端父路径不存在、包含链接或不是普通目录")
		}
		if current == p {
			attrs, ok := st.Sys().(*sftp.FileStat)
			if !ok || attrs.UID == 0 || owner != nil && attrs.UID != *owner || private && st.Mode().Perm() != 0700 || st.Mode().Perm()&0022 != 0 {
				return errors.New("远端目录必须由同一非 root 用户拥有；备份目录权限必须为 0700")
			}
		} else if st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0 {
			return errors.New("远端父目录允许其他用户改写且没有粘滞位")
		}
	}
	canonical, err := c.RealPath(p)
	if err != nil || canonical != p {
		return errors.New("远端目录规范路径改变，拒绝继续")
	}
	return nil
}
func remoteRoots(c *remoteSyncClient, cfg remoteSyncConfig) (uint32, error) {
	if err := remoteDirCheck(c, cfg.Target.Root, nil, false); err != nil {
		return 0, err
	}
	st, err := c.Lstat(cfg.Target.Root)
	if err != nil {
		return 0, err
	}
	owner := st.Sys().(*sftp.FileStat).UID
	if err = remoteDirCheck(c, cfg.Target.BackupRoot, &owner, true); err != nil {
		return 0, err
	}
	return owner, nil
}

func (s *Service) moduleRemoteSync(ctx context.Context, action string, in core.AppModuleInput) (out any, operationError error) {
	defer func() {
		var status *sftp.StatusError
		if errors.As(operationError, &status) {
			operationError = fmt.Errorf("SFTP 服务端状态码 %d；未回显不可信远端错误正文，请核对目录、权限和恢复记录", status.Code)
		}
	}()
	if action == "remote-plans" || strings.HasSuffix(action, "-remote-plan") {
		return s.moduleRemotePlans(action, in)
	}
	if action == "remote-targets" {
		entries, err := os.ReadDir(filepath.Join(s.remoteSyncDir(), "targets"))
		if errors.Is(err, os.ErrNotExist) {
			entries = nil
			err = nil
		}
		if err != nil {
			return nil, err
		}
		if len(entries) > 16 {
			return nil, errors.New("远端连接记录超过 16 个上限")
		}
		items := []map[string]any{}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				return nil, errors.New("远端连接目录包含未知记录")
			}
			c, err := s.readRemoteConfig(strings.TrimSuffix(e.Name(), ".json"))
			if err != nil {
				return nil, err
			}
			items = append(items, remotePublicConfig(c))
		}
		return map[string]any{"remote_targets": items, "scope": remoteSyncScope}, nil
	}
	if action == "cancel-remote" {
		return s.cancelRemoteSync(in)
	}
	if action == "remote-archive" {
		return s.remoteArchiveReport(in)
	}
	if action == "archive-remote-job" {
		return s.archiveRemoteJob(in)
	}
	if action == "remote-jobs" || action == "remote-job" {
		return s.remoteJobReport(in)
	}
	if !syncPlanID.MatchString(in.RemoteTargetID) {
		return nil, errors.New("请选择有效的远端连接标识")
	}
	if action == "save-remote" {
		if in.RemoteTarget == nil {
			return nil, errors.New("需要明确的远端 SFTP 连接策略")
		}
		if err := validateRemoteTarget(*in.RemoteTarget); err != nil {
			return nil, err
		}
		old, err := s.readRemoteConfig(in.RemoteTargetID)
		exists := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if exists && in.ExpectedRevision != old.Revision || !exists && in.ExpectedRevision != 0 {
			return nil, errors.New("远端连接修订号改变，请刷新后重试")
		}
		if busy, err := s.remoteTargetBusy(in.RemoteTargetID); err != nil || busy {
			return nil, errors.New("远端仍有排队、运行或待恢复任务，不能修改连接")
		}
		if exists && old.SpecSHA != remoteSpecSHA(*in.RemoteTarget) {
			return nil, errors.New("已有远端身份与目录不可修改；新目标请使用新连接标识，避免旧检查点误覆盖")
		}
		if !exists {
			entries, e := os.ReadDir(filepath.Join(s.remoteSyncDir(), "targets"))
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return nil, e
			}
			if len(entries) >= 16 {
				return nil, errors.New("最多 16 个远端连接")
			}
		}
		c := remoteSyncConfig{ID: in.RemoteTargetID, Target: *in.RemoteTarget, SpecSHA: remoteSpecSHA(*in.RemoteTarget), Revision: old.Revision + 1, Enabled: in.Enabled, AuthKind: old.AuthKind, Cipher: old.Cipher}
		if in.Password != "" && in.RemotePrivateKey != "" {
			return nil, errors.New("密码和私钥只能填写一种")
		}
		secret := []byte(in.Password)
		defer clear(secret)
		if in.RemotePrivateKey != "" {
			secret = []byte(in.RemotePrivateKey)
			defer clear(secret)
			c.AuthKind = "private-key"
			if _, e := ssh.ParsePrivateKey(secret); e != nil {
				return nil, errors.New("私钥无效或需要口令；认证材料未保存")
			}
		} else if len(secret) > 0 {
			c.AuthKind = "password"
		}
		if len(secret) > 32768 {
			return nil, errors.New("认证材料超过 32 KiB")
		}
		if len(secret) > 0 {
			c.Cipher, err = s.sealRemoteAuth(c, secret)
			if err != nil {
				return nil, err
			}
		} else if !exists {
			return nil, errors.New("新连接必须提供密码或私钥")
		}
		if err = moduleWrite(s.remoteConfigPath(c.ID), c); err != nil {
			return nil, err
		}
		return remotePublicConfig(c), nil
	}
	c, err := s.readRemoteConfig(in.RemoteTargetID)
	if err != nil {
		return nil, err
	}
	if action == "remote-backups" {
		if err = remoteBackupInput(in); err != nil {
			return nil, err
		}
		if in.ExpectedRevision != c.Revision {
			return nil, errors.New("连接修订号改变，请重新选择连接")
		}
	}
	if action == "queue-remote" {
		return s.queueRemoteSync(c, in)
	}
	if action == "recover-remote" {
		return s.recoverRemoteSync(ctx, c)
	}
	if !c.Enabled {
		return nil, errors.New("远端连接已停用")
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := s.dialRemoteSync(bounded, c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = remoteRoots(conn.client, c); err != nil {
		return nil, err
	}
	if action == "remote-backups" {
		return s.remoteBackupReport(conn.client, c, in)
	}
	if action == "probe-remote" {
		out := remotePublicConfig(c)
		out["ssh_host_key_verified"] = true
		out["sftp_subsystem"] = true
		out["scope"] = remoteSyncScope
		return out, nil
	}
	if action != "remote-preview" {
		return nil, errors.New("远端同步动作无效")
	}
	return s.previewRemoteSync(bounded, conn.client, c, in)
}

// Keep the port formatting local to transport policy, not a shell argument.
func stringPort(p int) string { return strconv.Itoa(p) }

func sortedRemoteFiles(m map[string]moduleFile) []string {
	p := make([]string, 0, len(m))
	for k := range m {
		p = append(p, k)
	}
	sort.Strings(p)
	return p
}
