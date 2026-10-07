//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type ftpServiceConfig struct {
	Revision       int64  `json:"revision"`
	BindAddress    string `json:"bind_address"`
	Port           int    `json:"port"`
	PassiveStart   int    `json:"passive_start"`
	PassiveEnd     int    `json:"passive_end"`
	PassiveAddress string `json:"passive_address"`
	CertificateID  string `json:"certificate_id"`
	Domain         string `json:"domain"`
	MaxClients     int    `json:"max_clients"`
	MaxPerIP       int    `json:"max_per_ip"`
	IdleMinutes    int    `json:"idle_minutes"`
}
type ftpServiceTransaction struct {
	ID              string `json:"id"`
	State           string `json:"state"`
	OldConfig       []byte `json:"old_config"`
	OldConfigExists bool   `json:"old_config_exists"`
	OldPEM          []byte `json:"old_pem"`
	NextConfigSHA   string `json:"next_config_sha"`
	NextPEMSHA      string `json:"next_pem_sha"`
	WasActive       bool   `json:"was_active"`
	Time            string `json:"time"`
}

func defaultFTPConfig() ftpServiceConfig {
	return ftpServiceConfig{BindAddress: "127.0.0.1", Port: 2121, PassiveStart: 30000, PassiveEnd: 30049, PassiveAddress: "127.0.0.1", MaxClients: 20, MaxPerIP: 4, IdleMinutes: 15}
}
func ftpPublicUsers(data []byte, sitesDir string) ([]map[string]any, error) {
	users := []map[string]any{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 6 || len(fields[0]) > 128 || strings.ContainsAny(fields[0], "\x00\r\t ") {
			return nil, errors.New("FTP 账户源文件格式损坏，未返回不完整列表")
		}
		uid, e := strconv.Atoi(fields[2])
		if e != nil || uid < 0 {
			return nil, errors.New("FTP 账户用户身份格式损坏")
		}
		gid, e := strconv.Atoi(fields[3])
		if e != nil || gid < 0 {
			return nil, errors.New("FTP 账户组身份格式损坏")
		}
		row := map[string]any{"username": fields[0], "uid": uid, "gid": gid, "home": fields[5]}
		limits, e := ftpLimitsFromFields(fields)
		if e != nil {
			return nil, e
		}
		row["expected_sha"] = core.Hash(line)
		row["quota_mb"], row["quota_files"] = limits.QuotaMB, limits.QuotaFiles
		row["upload_kb"], row["download_kb"], row["max_sessions"] = limits.UploadKB, limits.DownloadKB, limits.MaxSessions
		row["client_allow"], row["client_deny"] = limits.ClientAllow, limits.ClientDeny
		prefix := strings.TrimSuffix(sitesDir, "/") + "/"
		if sitesDir != "" && strings.HasPrefix(fields[5], prefix) {
			parts := strings.Split(strings.TrimPrefix(fields[5], prefix), "/")
			if len(parts) >= 2 && core.ValidID(parts[0]) && parts[1] == "public" {
				row["site_id"] = parts[0]
			}
		}
		users = append(users, row)
		if len(users) > 1000 {
			return nil, errors.New("FTP 账户列表超过显示上限，未返回不完整清单")
		}
	}
	return users, nil
}
func generateLocalFTPCertificate() ([]byte, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: serial, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-10 * time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})...), nil
}
func validateFTPConfig(c ftpServiceConfig) error {
	ip := net.ParseIP(c.BindAddress)
	if ip == nil || ip.To4() == nil || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4bcast) {
		return errors.New("监听地址必须为本机 IPv4 或 0.0.0.0")
	}
	passive := net.ParseIP(c.PassiveAddress)
	if passive == nil || passive.To4() == nil || passive.IsUnspecified() || passive.IsMulticast() || passive.IsLinkLocalUnicast() || passive.Equal(net.IPv4bcast) {
		return errors.New("被动模式通告地址必须为明确 IPv4，不能使用通配或域名")
	}
	if c.Port != 21 && (c.Port < 1024 || c.Port > 65535) {
		return errors.New("控制端口仅允许 21 或 1024–65535")
	}
	if c.PassiveStart < 1024 || c.PassiveEnd > 65535 || c.PassiveEnd < c.PassiveStart || c.PassiveEnd-c.PassiveStart < 1 || c.PassiveEnd-c.PassiveStart > 255 || c.Port >= c.PassiveStart && c.Port <= c.PassiveEnd {
		return errors.New("被动端口范围需为 1024–65535 中的 2–256 个连续端口，不能包含控制端口")
	}
	if c.MaxClients < 1 || c.MaxClients > 200 || c.MaxPerIP < 1 || c.MaxPerIP > 20 || c.MaxPerIP > c.MaxClients || c.IdleMinutes < 1 || c.IdleMinutes > 60 || c.Revision < 0 {
		return errors.New("连接总数 1–200、单 IP 1–20 且不超过总数，空闲超时 1–60 分钟")
	}
	if c.CertificateID != "" && (!core.ValidID(c.CertificateID) || !core.ValidDomain(c.Domain)) {
		return errors.New("请选择有效证书并填写该证书覆盖的 FTP 域名")
	}
	if c.CertificateID == "" && (!ip.IsLoopback() || c.Domain != "") {
		return errors.New("非回环监听必须选择有效域名证书，不能使用默认本地自签名证书")
	}
	return nil
}
func ftpPrivateRead(path string, limit int64) ([]byte, error) {
	if err := ownedRuntimePath(path, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("FTP 私有配置与证书必须为 root 独占的常规文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("FTP 配置文件超出上限")
	}
	return data, nil
}
func (s *Service) ftpConfig() (ftpServiceConfig, error) {
	c := defaultFTPConfig()
	b, e := ftpPrivateRead(filepath.Join(s.moduleDir("pure-ftpd"), "service.json"), 16<<10)
	if errors.Is(e, os.ErrNotExist) {
		return c, nil
	}
	if e != nil {
		return c, e
	}
	c = ftpServiceConfig{}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, errors.New("FTP 服务配置损坏，未使用宽松默认值")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("FTP 服务配置有多余内容")
	}
	if c.Revision < 1 {
		return c, errors.New("FTP 已保存配置缺少有效修订号")
	}
	return c, validateFTPConfig(c)
}
func (s *Service) lockFTP() (*os.File, error) {
	p := filepath.Join(s.moduleDir("pure-ftpd"), "service.lock")
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	if e = ownedRuntimePath(p, false); e == nil {
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if e != nil {
		f.Close()
		return nil, errors.New("FTP 配置正被恢复或修改，请刷新重试")
	}
	return f, nil
}
func (s *Service) ftpCertificate(c ftpServiceConfig) ([]byte, map[string]any, error) {
	var data []byte
	meta := map[string]any{"source": "local-self-signed", "trusted": false, "domain": "localhost"}
	if c.CertificateID != "" {
		f := certificateFS{root: s.systemPath(certificateRoot)}
		cert, e := f.load(c.CertificateID)
		if e != nil {
			return nil, nil, e
		}
		if e = cert.ValidateDomains(c.Domain, nil, time.Now()); e != nil {
			return nil, nil, e
		}
		if !net.ParseIP(c.BindAddress).IsLoopback() && !cert.Trusted {
			return nil, nil, errors.New("非回环 FTPS 证书必须通过本机系统信任链校验；私有 CA 需先安全安装至系统信任库")
		}
		key, e := f.readFile(c.CertificateID, "key.pem", 16384, true)
		if e != nil {
			return nil, nil, e
		}
		data = append(append([]byte(cert.PEM), '\n'), key...)
		meta = map[string]any{"source": "panel-certificate", "id": c.CertificateID, "domain": c.Domain, "trusted": cert.Trusted, "fingerprint": cert.Fingerprint, "not_after": cert.NotAfter, "status": cert.Status}
	} else {
		var e error
		localPath := filepath.Join(s.moduleDir("pure-ftpd"), "local.pem")
		if !exists(localPath) {
			current, configErr := s.ftpConfig()
			if configErr != nil {
				return nil, nil, configErr
			}
			if current.CertificateID != "" {
				return nil, nil, errors.New("本地默认证书缺失，拒绝将现用域名证书冒充为默认证书")
			}
			localPath = filepath.Join(s.moduleDir("pure-ftpd"), "server.pem")
		}
		data, e = ftpPrivateRead(localPath, 49152)
		if e != nil {
			return nil, nil, e
		}
	}
	pair, e := tls.X509KeyPair(data, data)
	if e != nil {
		return nil, nil, errors.New("FTP TLS 证书与私钥不匹配")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, nil, e
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, nil, errors.New("FTP 证书已过期或尚未生效，请先更换证书")
	}
	meta["not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	return data, meta, nil
}
func ftpArguments(c ftpServiceConfig, dir string) []string {
	return []string{"-4", "-u", "1", "-S", c.BindAddress + "," + strconv.Itoa(c.Port), "-p", fmt.Sprintf("%d:%d", c.PassiveStart, c.PassiveEnd), "-P", c.PassiveAddress, "-A", "-E", "-H", "-j", "-c", strconv.Itoa(c.MaxClients), "-C", strconv.Itoa(c.MaxPerIP), "-I", strconv.Itoa(c.IdleMinutes), "-l", "puredb:" + filepath.Join(dir, "users.pdb"), "-Y", "3", "-2", filepath.Join(dir, "server.pem")}
}
func readFTPReply(r *bufio.Reader, code string) error {
	for n := 0; n < 32; n++ {
		lineBytes, e := r.ReadSlice('\n')
		if e != nil {
			return e
		}
		line := string(lineBytes)
		if len(line) > 4096 {
			return errors.New("FTP 响应过长")
		}
		if strings.HasPrefix(line, code+" ") {
			return nil
		}
		if n == 0 && !strings.HasPrefix(line, code+"-") {
			return errors.New("FTP 响应状态不符合要求")
		}
	}
	return errors.New("FTP 多行响应超限")
}
func (s *Service) ftpReady(ctx context.Context, c ftpServiceConfig, pemBytes []byte) error {
	if s.Config.SystemRoot != "/" {
		_, e := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pure-ftpd.service")
		return e
	}
	pair, e := tls.X509KeyPair(pemBytes, pemBytes)
	if e != nil {
		return e
	}
	fingerprint := sha256.Sum256(pair.Certificate[0])
	host := c.BindAddress
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, e := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(c.Port)))
		if e == nil {
			_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
			r := bufio.NewReader(conn)
			if e = readFTPReply(r, "220"); e == nil {
				_, e = io.WriteString(conn, "AUTH TLS\r\n")
			}
			if e == nil {
				e = readFTPReply(r, "234")
			}
			if e == nil {
				// Pin the exact locally validated leaf; do not trust a process merely
				// because it has opened the port. No login/password is sent by this probe.
				config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
					if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != fingerprint {
						return errors.New("FTP 监听证书不是刚保存的证书")
					}
					return nil
				}}
				e = tls.Client(conn, config).HandshakeContext(ctx)
			}
			conn.Close()
			if e == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return errors.New("FTPS 控制通道与证书探测失败，未将端口监听当作验收通过")
}
func (s *Service) finishFTPTransaction(t ftpServiceTransaction) error {
	pending := filepath.Join(s.moduleDir("pure-ftpd"), "pending-service.json")
	if e := moduleWrite(pending, t); e != nil {
		return e
	}
	if e := moduleWrite(filepath.Join(s.moduleDir("pure-ftpd"), "service-transactions", t.ID+".json"), t); e != nil {
		return e
	}
	return os.Remove(pending)
}
func (s *Service) recoverFTPTransaction() (bool, error) {
	pending := filepath.Join(s.moduleDir("pure-ftpd"), "pending-service.json")
	var t ftpServiceTransaction
	if e := moduleRead(pending, &t); errors.Is(e, os.ErrNotExist) {
		return false, nil
	} else if e != nil {
		return false, e
	}
	if !core.ValidID(t.ID) || (t.State != "applying" && t.State != "committed" && t.State != "recovered") {
		return false, errors.New("FTP 恢复记录损坏")
	}
	if t.State != "applying" {
		return false, s.finishFTPTransaction(t)
	}
	if len(t.OldConfig) > 16<<10 || len(t.OldPEM) == 0 || len(t.OldPEM) > 49152 || len(t.NextConfigSHA) != 64 || len(t.NextPEMSHA) != 64 {
		return false, errors.New("FTP 恢复备份不完整")
	}
	for _, file := range []struct {
		name   string
		old    []byte
		next   string
		exists bool
	}{{"service.json", t.OldConfig, t.NextConfigSHA, t.OldConfigExists}, {"server.pem", t.OldPEM, t.NextPEMSHA, true}} {
		path := filepath.Join(s.moduleDir("pure-ftpd"), file.name)
		current, e := ftpPrivateRead(path, 49152)
		if errors.Is(e, os.ErrNotExist) && !file.exists {
			continue
		}
		if e != nil {
			return false, e
		}
		hash := core.Hash(string(current))
		if hash != file.next && (!file.exists || hash != core.Hash(string(file.old))) {
			return false, errors.New("FTP 配置被外部修改，拒绝自动覆盖；请保留恢复备份并人工核对")
		}
	}
	// Validate both files before changing either of them; root-owned atomic
	// replacement ensures recovery itself can be repeated after interruption.
	if t.OldConfigExists {
		if e := atomicWrite(filepath.Join(s.moduleDir("pure-ftpd"), "service.json"), t.OldConfig, 0600); e != nil {
			return false, e
		}
	} else if e := os.Remove(filepath.Join(s.moduleDir("pure-ftpd"), "service.json")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	if e := atomicWrite(filepath.Join(s.moduleDir("pure-ftpd"), "server.pem"), t.OldPEM, 0600); e != nil {
		return false, e
	}
	t.State = "recovered"
	return t.WasActive, s.finishFTPTransaction(t)
}
func RecoverPureFTP() error {
	s := New(Config{})
	if !s.moduleInstalled("pure-ftpd") {
		return nil
	}
	lock, e := s.lockFTP()
	if e != nil {
		return e
	}
	defer lock.Close()
	_, e = s.recoverFTPTransaction()
	if e != nil {
		return e
	}
	if e = s.recoverFTPAccounts(); e != nil {
		return e
	}
	_, e = s.recoverFTPRuntime()
	return e
}
func ServePureFTP() error {
	s := New(Config{})
	if !s.moduleInstalled("pure-ftpd") {
		return errors.New("FTP 模块未安装")
	}
	if exists(filepath.Join(s.moduleDir("pure-ftpd"), "pending-accounts.json")) || exists(filepath.Join(s.moduleDir("pure-ftpd"), "pending-service.json")) {
		return errors.New("FTP 有未完成事务，必须先恢复再启动")
	}
	c, e := s.ftpConfig()
	if e != nil {
		return e
	}
	data, _, e := s.ftpCertificate(c)
	if e != nil {
		return e
	}
	current, e := ftpPrivateRead(filepath.Join(s.moduleDir("pure-ftpd"), "server.pem"), 49152)
	if e != nil {
		return e
	}
	if !bytes.Equal(data, current) {
		return errors.New("FTP 服务证书与受管配置不符")
	}
	binary, e := s.ftpBinary("pure-ftpd")
	if e != nil {
		return e
	}
	args := append([]string{binary}, ftpArguments(c, s.moduleDir("pure-ftpd"))...)
	return syscall.Exec(args[0], args, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"})
}
func (s *Service) configureFTP(ctx context.Context, in core.AppModuleInput) (any, error) {
	// Complete boot recovery before recording a new transaction. The oneshot
	// remains active, so a candidate service restart does not restore the old set.
	if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "panel-pure-ftpd-recover.service"); e != nil {
		return nil, e
	}
	lock, e := s.lockFTP()
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if s.ftpRecoveryPending() {
		return nil, errors.New("FTP 有未完成的配置，请先执行恢复")
	}
	old, e := s.ftpConfig()
	if e != nil {
		return nil, e
	}
	if in.ExpectedRevision != old.Revision {
		return nil, errors.New("FTP 配置修订号已变化，请先刷新服务配置")
	}
	localPath := filepath.Join(s.moduleDir("pure-ftpd"), "local.pem")
	if old.CertificateID == "" && !exists(localPath) {
		original, e := ftpPrivateRead(filepath.Join(s.moduleDir("pure-ftpd"), "server.pem"), 49152)
		if e != nil {
			return nil, e
		}
		f, e := os.OpenFile(localPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return nil, e
		}
		_, e = f.Write(original)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return nil, e
		}
	}
	next := ftpServiceConfig{Revision: old.Revision + 1, BindAddress: in.BindAddress, Port: in.Port, PassiveStart: in.PassiveStart, PassiveEnd: in.PassiveEnd, PassiveAddress: in.PassiveAddress, CertificateID: in.CertificateID, Domain: in.Domain, MaxClients: in.MaxClients, MaxPerIP: in.MaxPerIP, IdleMinutes: in.IdleMinutes}
	if e = validateFTPConfig(next); e != nil {
		return nil, e
	}
	ip := net.ParseIP(next.BindAddress)
	if !ip.IsLoopback() && in.Confirm != "EXPOSE FTPS "+next.BindAddress+":"+strconv.Itoa(next.Port) {
		return nil, errors.New("非回环监听会改变网络暴露面，确认字段须为 EXPOSE FTPS " + next.BindAddress + ":" + strconv.Itoa(next.Port))
	}
	if !ip.IsUnspecified() && !ip.IsLoopback() && s.Config.SystemRoot == "/" {
		addresses, e := net.InterfaceAddrs()
		if e != nil {
			return nil, e
		}
		local := false
		for _, address := range addresses {
			addressIP, _, _ := net.ParseCIDR(address.String())
			if addressIP.Equal(ip) {
				local = true
			}
		}
		if !local {
			return nil, errors.New("监听 IP 不属于本机接口")
		}
	}
	pemBytes, meta, e := s.ftpCertificate(next)
	if e != nil {
		return nil, e
	}
	oldPEM, e := ftpPrivateRead(filepath.Join(s.moduleDir("pure-ftpd"), "server.pem"), 49152)
	if e != nil {
		return nil, e
	}
	configPath := filepath.Join(s.moduleDir("pure-ftpd"), "service.json")
	oldBytes, e := ftpPrivateRead(configPath, 16<<10)
	oldExists := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	nextBytes, e := json.MarshalIndent(next, "", "  ")
	if e != nil {
		return nil, e
	}
	nextBytes = append(nextBytes, '\n')
	state, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pure-ftpd.service")
	active := strings.TrimSpace(state) == "active"
	t := ftpServiceTransaction{ID: core.ID(), State: "applying", OldConfig: oldBytes, OldConfigExists: oldExists, OldPEM: oldPEM, NextConfigSHA: core.Hash(string(nextBytes)), NextPEMSHA: core.Hash(string(pemBytes)), WasActive: active, Time: core.Now()}
	rows, _ := filepath.Glob(filepath.Join(s.moduleDir("pure-ftpd"), "service-transactions", "*.json"))
	if len(rows) >= 512 {
		return nil, errors.New("FTP 配置恢复记录达到 512 条，先安全归档旧备份")
	}
	if e = moduleWrite(filepath.Join(s.moduleDir("pure-ftpd"), "pending-service.json"), t); e != nil {
		return nil, e
	}
	rollback := func(cause error) (any, error) {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, restoreErr := s.recoverFTPTransaction()
		if restoreErr != nil {
			return nil, errors.New("FTP 配置失败，自动恢复未完成；恢复备份已保留")
		}
		if active {
			_, restoreErr = s.Config.Run(recoveryCtx, "/usr/bin/systemctl", "restart", "panel-pure-ftpd.service")
			if restoreErr == nil {
				restoreErr = s.ftpReady(recoveryCtx, old, oldPEM)
			}
		}
		if restoreErr != nil {
			return nil, errors.New("FTP 配置已恢复，但旧服务未就绪；请核对服务日志")
		}
		return nil, cause
	}
	if e = atomicWrite(filepath.Join(s.moduleDir("pure-ftpd"), "server.pem"), pemBytes, 0600); e != nil {
		return rollback(e)
	}
	if e = atomicWrite(configPath, nextBytes, 0600); e != nil {
		return rollback(e)
	}
	if active {
		if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "panel-pure-ftpd.service"); e != nil {
			return rollback(e)
		}
		if e = s.ftpReady(ctx, next, pemBytes); e != nil {
			return rollback(e)
		}
	}
	t.State = "committed"
	if e = s.finishFTPTransaction(t); e != nil {
		return nil, errors.New("FTP 配置可能已应用，但提交记录保存失败；请刷新核对并保留恢复记录")
	}
	return map[string]any{"ok": true, "config": next, "certificate": meta, "service_active": active, "firewall_changed": false, "restart_verified": active, "backup_id": t.ID}, nil
}
