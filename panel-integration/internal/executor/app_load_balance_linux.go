//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// HTTP entries are bound to loopback. This record never claims an OSS TCP
// connection probe is an active application health check.
type loadBalanceEntry struct {
	Format      int                         `json:"format"`
	Revision    int64                       `json:"revision"`
	Domain      string                      `json:"domain"`
	Port        int                         `json:"port"`
	Nodes       []core.AppUpstream          `json:"nodes"`
	Sticky      bool                        `json:"sticky"`
	Removed     bool                        `json:"removed"`
	HealthCheck *core.LoadBalanceHTTPHealth `json:"health_check,omitempty"`
	BackendTLS  *core.LoadBalanceBackendTLS `json:"backend_tls,omitempty"`
}
type loadBalanceTransaction struct {
	Format    int               `json:"format"`
	ID        string            `json:"id"`
	Domain    string            `json:"domain"`
	State     string            `json:"state"`
	CreatedAt string            `json:"created_at"`
	Changes   []wafConfigChange `json:"changes"`
	Digests   map[string]string `json:"digests"`
}

func loadBalancePrivateRead(path string, limit int64) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &st); e != nil {
		return nil, e
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size > limit {
		return nil, errors.New("负载均衡私有记录身份、权限、链接数或大小异常")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("负载均衡私有记录超限")
	}
	return b, nil
}

func validateLoadBalanceEntry(v loadBalanceEntry) error {
	if e := core.ValidateLoadBalanceBackendTLS(v.BackendTLS); e != nil {
		return e
	}
	if (v.Format == 2) != (v.BackendTLS != nil) {
		return errors.New("TLS 入口须使用格式 2；历史 HTTP 清单不得自动启用 TLS")
	}
	if b, e := json.Marshal(v); e != nil || len(b) > 32<<10 {
		return errors.New("入口清单、检查策略与 CA 总计最多 32 KiB")
	}
	if e := core.ValidateLoadBalanceHTTPHealth(v.HealthCheck); e != nil {
		return e
	}
	if v.Format == 0 && v.HealthCheck != nil {
		return errors.New("历史入口不能冒充已登记 HTTP 检查策略")
	}
	if !core.ValidDomain(v.Domain) || strings.ToLower(v.Domain) != v.Domain || v.Port < 20000 || v.Port > 60000 ||
		len(v.Nodes) < 2 || len(v.Nodes) > 16 || (v.Format != 0 && v.Format != 1 && v.Format != 2) || v.Revision < 0 || v.Revision >= 1<<60 ||
		(v.Format == 0 && (v.Revision != 0 || v.Removed)) || (v.Format > 0 && v.Revision == 0) {
		return errors.New("负载均衡入口身份、修订号、端口或节点数量无效")
	}
	seen := map[string]bool{}
	healthTargets := map[string]bool{}
	primary := 0
	for _, n := range v.Nodes {
		ip, p, e := loadBalanceNodeAddress(n.Address)
		if e != nil ||
			n.Weight < 1 || n.Weight > 100 || seen[n.Address] || (n.Backup && v.Sticky) ||
			(ip.IsLoopback() && (p == v.Port || p == 19100 || p == 19102 || p == 19080)) {
			return errors.New("上游须为唯一规范固定 IP:端口；拒绝自循环、面板控制端口、链路本地/组播/映射地址与非法权重，粘滞不能使用备用节点")
		}
		seen[n.Address] = true
		if v.HealthCheck != nil {
			target, err := loadBalanceHealthAddress(v, n.Address)
			if err != nil || healthTargets[target] || (v.BackendTLS == nil && v.HealthCheck.Scheme == "https" && v.HealthCheck.CheckPort == p) ||
				(v.BackendTLS != nil && v.HealthCheck.CheckPort == 0 && v.HealthCheck.Scheme != "https") {
				return errors.New("检查须使用唯一固定节点 IP 和安全端口；HTTPS 就绪端口必须独立于 HTTP 转发端口")
			}
			healthTargets[target] = true
		}
		if !n.Backup {
			primary++
		}
	}
	if primary == 0 {
		return errors.New("至少保留一个主节点，不能全部设置为备用")
	}
	return nil
}
func loadBalanceNodeAddress(address string) (netip.Addr, int, error) {
	host, port, e := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	p, portErr := strconv.Atoi(port)
	if e != nil || ipErr != nil || portErr != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() ||
		ip.Is4In6() || ip.Zone() != "" || ip == netip.MustParseAddr("255.255.255.255") || ip == netip.MustParseAddr("fd00:ec2::254") || ip == netip.MustParseAddr("100.100.100.200") ||
		p < 1 || p > 65535 || port != strconv.Itoa(p) || address != net.JoinHostPort(ip.String(), port) {
		return netip.Addr{}, 0, errors.New("上游不是允许的规范固定 IP:端口")
	}
	return ip, p, nil
}
func decodeLoadBalanceEntry(b []byte) (loadBalanceEntry, error) {
	var head struct {
		Format int `json:"format"`
	}
	if len(b) > 32<<10 || json.Unmarshal(b, &head) != nil {
		return loadBalanceEntry{}, errors.New("负载均衡清单损坏或超限")
	}
	var v loadBalanceEntry
	if head.Format == 0 {
		var old struct {
			Domain string             `json:"domain"`
			Port   int                `json:"port"`
			Nodes  []core.AppUpstream `json:"nodes"`
			Sticky bool               `json:"sticky"`
		}
		if e := decodeFTPPrivateJSON(b, &old); e != nil {
			return v, e
		}
		v = loadBalanceEntry{Domain: old.Domain, Port: old.Port, Nodes: old.Nodes, Sticky: old.Sticky}
	} else if e := decodeFTPPrivateJSON(b, &v); e != nil {
		return v, e
	}
	return v, validateLoadBalanceEntry(v)
}
func loadBalanceID(domain string) string { return core.Hash(domain)[:20] }
func loadBalanceFingerprint(v loadBalanceEntry) string {
	b, _ := json.Marshal(v)
	return loadBalanceID(v.Domain) + ":" + strconv.FormatInt(v.Revision, 10) + ":" + core.Hash(string(b))[:24]
}
func loadBalanceProbePath(domain string) string {
	return "/__yunzhan_lb_health/" + loadBalanceID(domain)
}
func renderLoadBalanceEntry(v loadBalanceEntry) (string, error) {
	return renderLoadBalanceEntryTrust(v, "")
}
func renderLoadBalanceEntryTrust(v loadBalanceEntry, trustPath string) (string, error) {
	if e := validateLoadBalanceEntry(v); e != nil {
		return "", e
	}
	if v.BackendTLS != nil && (trustPath == "" || !filepath.IsAbs(trustPath) || filepath.Clean(trustPath) != trustPath || strings.ContainsAny(trustPath, "\r\n\x00\"'\\$;{}")) {
		return "", errors.New("TLS 入口缺少固定受管 CA 路径")
	}
	var b strings.Builder
	id := loadBalanceID(v.Domain)
	if v.Format > 0 {
		fmt.Fprintf(&b, "# managed by panel; load-balance=%s; revision=%d\n", id, v.Revision)
	}
	fmt.Fprintf(&b, "upstream panel_lb_%s {\n", id)
	if v.Sticky {
		b.WriteString("  ip_hash;\n")
	}
	for _, n := range v.Nodes {
		backup := ""
		if n.Backup {
			backup = " backup"
		}
		fmt.Fprintf(&b, "  server %s weight=%d max_fails=1 fail_timeout=5s%s;\n", n.Address, n.Weight, backup)
	}
	if v.Format == 0 {
		// Exact historical renderer: a manual edit is never silently adopted.
		fmt.Fprintf(&b, "}\nserver { listen 127.0.0.1:%d; server_name %s; location / { proxy_pass http://panel_lb_%s; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_connect_timeout 2s; proxy_read_timeout 30s; proxy_next_upstream error timeout http_502 http_503 http_504; } }\n", v.Port, v.Domain, id)
	} else {
		fmt.Fprintf(&b, "}\nserver {\n  listen 127.0.0.1:%d;\n  server_name %s;\n  location = %s { default_type text/plain; access_log off; return 200 '%s'; }\n  location / {\n    proxy_pass http://panel_lb_%s;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_connect_timeout 2s;\n    proxy_read_timeout 30s;\n    proxy_next_upstream error timeout http_502 http_503 http_504;\n  }\n}\n", v.Port, v.Domain, loadBalanceProbePath(v.Domain), loadBalanceFingerprint(v), id)
	}
	if v.BackendTLS != nil {
		value := b.String()
		value = strings.Replace(value, "proxy_pass http://panel_lb_", "proxy_pass https://panel_lb_", 1)
		value = strings.Replace(value, "proxy_set_header Host $host;", "proxy_set_header Host "+v.BackendTLS.ServerName+";", 1)
		tls := fmt.Sprintf("    proxy_ssl_server_name on;\n    proxy_ssl_name %s;\n    proxy_ssl_verify on;\n    proxy_ssl_verify_depth 4;\n    proxy_ssl_protocols TLSv1.2 TLSv1.3;\n    proxy_ssl_trusted_certificate \"%s\";\n", v.BackendTLS.ServerName, trustPath)
		value = strings.Replace(value, "    proxy_connect_timeout 2s;", tls+"    proxy_connect_timeout 2s;", 1)
		return value, nil
	}
	return b.String(), nil
}
func (s *Service) loadBalanceCAPath(domain string) string {
	return filepath.Join(s.moduleDir("load-balance"), "backend-ca", loadBalanceID(domain)+".pem")
}
func (s *Service) renderLoadBalanceEntry(v loadBalanceEntry) (string, error) {
	return renderLoadBalanceEntryTrust(v, s.loadBalanceCAPath(v.Domain))
}
func loadBalanceCAState(v loadBalanceEntry) (bool, []byte) {
	if v.BackendTLS == nil || v.Removed {
		return false, nil
	}
	return true, []byte(v.BackendTLS.CAPEM)
}
func (s *Service) verifyLoadBalanceCA(v loadBalanceEntry) error {
	path := s.loadBalanceCAPath(v.Domain)
	want, data := loadBalanceCAState(v)
	if e := s.wafOwnedDirectory(filepath.Dir(path), false); e != nil {
		if errors.Is(e, os.ErrNotExist) && !want {
			return nil // An absent owned parent is absence, not an invented CA.
		}
		return e
	}
	mode := os.FileMode(0)
	if want {
		mode = 0600
	}
	match, e := s.wafCurrentMatches(wafConfigChange{Path: path, OldExists: want, OldMode: mode, OldData: data}, false)
	if e != nil || !match {
		return errors.New("入口专用 CA 与可信清单不一致；保留外部修改，拒绝覆盖")
	}
	return nil
}
func (s *Service) loadBalancePaths(domain string) (string, string) {
	id := loadBalanceID(domain)
	return filepath.Join(s.Config.ConfDir, "load-balance-"+id+".conf"), filepath.Join(s.moduleDir("load-balance"), "balancers", id+".json")
}
func (s *Service) loadBalancePendingPath() string {
	return filepath.Join(s.moduleDir("load-balance"), "transactions", "pending.json")
}
func (s *Service) readLoadBalanceEntry(domain string) (loadBalanceEntry, bool, error) {
	conf, meta := s.loadBalancePaths(domain)
	if e := s.wafOwnedDirectory(filepath.Dir(meta), false); e != nil {
		if !errors.Is(e, os.ErrNotExist) {
			return loadBalanceEntry{}, false, e
		}
	}
	b, e := loadBalancePrivateRead(meta, 32<<10)
	if errors.Is(e, os.ErrNotExist) {
		if _, e := os.Lstat(conf); !errors.Is(e, os.ErrNotExist) {
			return loadBalanceEntry{}, false, errors.New("入口配置没有对应可信清单，拒绝接管")
		}
		return loadBalanceEntry{}, false, nil
	}
	if e != nil {
		return loadBalanceEntry{}, false, e
	}
	v, e := decodeLoadBalanceEntry(b)
	if e != nil || v.Domain != domain {
		return v, false, errors.New("入口清单身份或内容无效")
	}
	if e := s.verifyLoadBalanceCA(v); e != nil {
		return v, false, e
	}
	expected, e := s.renderLoadBalanceEntry(v)
	if e != nil {
		return v, false, e
	}
	c := wafConfigChange{Path: conf, OldExists: !v.Removed, OldMode: 0644, OldData: []byte(expected)}
	match, e := s.wafCurrentMatches(c, false)
	if e != nil || !match {
		return v, false, errors.New("入口配置与清单不一致；保留外部修改，不覆盖或伪造健康")
	}
	return v, true, nil
}
func (s *Service) loadBalanceEntries() ([]loadBalanceEntry, error) {
	dir := filepath.Join(s.moduleDir("load-balance"), "balancers")
	if e := s.wafOwnedDirectory(dir, false); errors.Is(e, os.ErrNotExist) {
		return []loadBalanceEntry{}, nil
	} else if e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if len(entries) > 256 {
		return nil, errors.New("负载均衡记录超过 256 项，拒绝不完整列表")
	}
	out := []loadBalanceEntry{}
	ports := map[int]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") || len(entry.Name()) != 25 {
			return nil, errors.New("入口目录存在未知或非普通条目，拒绝部分读取")
		}
		b, e := loadBalancePrivateRead(filepath.Join(dir, entry.Name()), 32<<10)
		if e != nil {
			return nil, e
		}
		v, e := decodeLoadBalanceEntry(b)
		if e != nil || entry.Name() != loadBalanceID(v.Domain)+".json" {
			return nil, errors.New("入口清单与文件标识不一致")
		}
		if _, _, e = s.readLoadBalanceEntry(v.Domain); e != nil {
			return nil, e
		}
		if !v.Removed {
			if ports[v.Port] {
				return nil, errors.New("不同入口登记了同一回环端口")
			}
			ports[v.Port] = true
			out = append(out, v)
		}
	}
	if len(out) > 64 {
		return nil, errors.New("最多 64 个活动入口")
	}
	return out, nil
}
func (s *Service) loadBalanceTransactionContract(tx loadBalanceTransaction) error {
	count := 2
	if tx.Format == 2 {
		count = 3
	}
	if (tx.Format != 1 && tx.Format != 2) || !core.ValidID(tx.ID) || !core.ValidDomain(tx.Domain) || len(tx.Changes) != count || len(tx.Digests) != count*2 ||
		(tx.State != "applying" && tx.State != "restored" && tx.State != "recovered" && tx.State != "committed") {
		return errors.New("负载均衡事务身份、状态或条目无效")
	}
	if _, e := time.Parse(time.RFC3339, tx.CreatedAt); e != nil {
		return e
	}
	conf, meta := s.loadBalancePaths(tx.Domain)
	if tx.Changes[0].Path != conf || tx.Changes[1].Path != meta {
		return errors.New("恢复事务目标不属于指定入口")
	}
	if tx.Format == 2 && tx.Changes[2].Path != s.loadBalanceCAPath(tx.Domain) {
		return errors.New("恢复事务 CA 目标不属于指定入口")
	}
	for _, c := range tx.Changes {
		if len(c.OldData) > 32<<10 || len(c.NextData) > 32<<10 || tx.Digests[c.Path+":old"] != core.Hash(string(c.OldData)) || tx.Digests[c.Path+":next"] != core.Hash(string(c.NextData)) ||
			(!c.OldExists && (len(c.OldData) != 0 || c.OldMode != 0)) || (!c.NextExists && (len(c.NextData) != 0 || c.NextMode != 0)) {
			return errors.New("负载均衡事务恢复内容、权限或摘要无效")
		}
	}
	cm, mm := tx.Changes[0], tx.Changes[1]
	if !mm.NextExists || mm.NextMode != 0600 || (mm.OldExists && mm.OldMode != 0600) ||
		(cm.OldExists && cm.OldMode != 0644) || (cm.NextExists && cm.NextMode != 0644) {
		return errors.New("恢复事务文件权限不符合固定契约")
	}
	next, e := decodeLoadBalanceEntry(mm.NextData)
	if e != nil || next.Format == 0 || next.Domain != tx.Domain {
		return errors.New("恢复事务下一清单无效")
	}
	old := loadBalanceEntry{}
	if mm.OldExists {
		old, e = decodeLoadBalanceEntry(mm.OldData)
		if e != nil || old.Domain != tx.Domain {
			return errors.New("恢复事务原清单无效")
		}
		rendered, e := s.renderLoadBalanceEntry(old)
		if e != nil || cm.OldExists == old.Removed || (cm.OldExists && string(cm.OldData) != rendered) {
			return errors.New("恢复事务原配置不匹配可信原清单")
		}
	} else if cm.OldExists {
		return errors.New("无原清单的配置不能接管")
	}
	if (tx.Format == 2) != (old.BackendTLS != nil || next.BackendTLS != nil) {
		return errors.New("TLS 变更必须完整绑定 CA、配置和清单；历史 HTTP 事务保持两文件契约")
	}
	if tx.Format == 2 {
		c := tx.Changes[2]
		oldExists, oldData := loadBalanceCAState(old)
		nextExists, nextData := loadBalanceCAState(next)
		if c.OldExists != oldExists || c.NextExists != nextExists ||
			!bytes.Equal(c.OldData, oldData) || !bytes.Equal(c.NextData, nextData) ||
			(oldExists && c.OldMode != 0600) || (nextExists && c.NextMode != 0600) {
			return errors.New("TLS 恢复事务 CA 内容、存在状态或权限不符合清单")
		}
	}
	rendered, e := s.renderLoadBalanceEntry(next)
	if e != nil || cm.NextExists == next.Removed || (cm.NextExists && string(cm.NextData) != rendered) || next.Revision != old.Revision+1 ||
		(next.Removed && (!mm.OldExists || old.Removed)) {
		return errors.New("恢复事务新配置、修订号或移除契约异常")
	}
	if next.Removed {
		expected := old
		if expected.Format == 0 {
			expected.Format = 1
		}
		expected.Revision++
		expected.Removed = true
		a, _ := json.Marshal(expected)
		b, _ := json.Marshal(next)
		if !bytes.Equal(a, b) {
			return errors.New("移除事务不得修改原节点或入口身份")
		}
	}
	return nil
}
func (s *Service) writeLoadBalanceTransaction(path string, tx loadBalanceTransaction) error {
	if e := s.loadBalanceTransactionContract(tx); e != nil {
		return e
	}
	if e := s.wafOwnedDirectory(filepath.Dir(path), true); e != nil {
		return e
	}
	dir := filepath.Dir(s.loadBalancePendingPath())
	if path != s.loadBalancePendingPath() && path != filepath.Join(dir, tx.ID+".json") {
		return errors.New("事务写入目标不属于固定私有目录")
	}
	if b, e := loadBalancePrivateRead(path, 256<<10); e == nil {
		var previous loadBalanceTransaction
		if decodeFTPPrivateJSON(b, &previous) != nil || s.loadBalanceTransactionContract(previous) != nil || previous.ID != tx.ID {
			return errors.New("旧事务记录异常，拒绝覆盖")
		}
		oldState := previous.State
		previous.State = tx.State
		a, _ := json.Marshal(previous)
		b, _ = json.Marshal(tx)
		if !bytes.Equal(a, b) || (oldState == "committed" && tx.State != "committed") || (oldState == "recovered" && tx.State != "recovered") {
			return errors.New("事务不可更改原始恢复内容或回退已完成状态")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return moduleWrite(path, tx)
}
func (s *Service) finishLoadBalanceTransaction(tx loadBalanceTransaction) error {
	pending := s.loadBalancePendingPath()
	if e := s.writeLoadBalanceTransaction(pending, tx); e != nil {
		return e
	}
	if e := s.writeLoadBalanceTransaction(filepath.Join(filepath.Dir(pending), tx.ID+".json"), tx); e != nil {
		return e
	}
	if e := os.Remove(pending); e != nil {
		return e
	}
	f, e := os.Open(filepath.Dir(pending))
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *Service) readLoadBalanceTransaction() (loadBalanceTransaction, error) {
	var tx loadBalanceTransaction
	p := s.loadBalancePendingPath()
	if e := s.wafOwnedDirectory(filepath.Dir(p), false); e != nil {
		return tx, e
	}
	b, e := loadBalancePrivateRead(p, 256<<10)
	if e != nil {
		return tx, e
	}
	if e = decodeFTPPrivateJSON(b, &tx); e != nil {
		return tx, e
	}
	return tx, s.loadBalanceTransactionContract(tx)
}

// Validate the entire old/new set before the first restore. Unknown external
// edits stay untouched, even when the other file is an interrupted new version.
// The "restored" pending record is kept until hot reload/cold syntax validation.
func (s *Service) restoreLoadBalanceTransaction() (loadBalanceTransaction, bool, error) {
	tx, e := s.readLoadBalanceTransaction()
	if errors.Is(e, os.ErrNotExist) {
		return tx, false, nil
	}
	if e != nil {
		return tx, false, e
	}
	wantNext := tx.State == "committed"
	wantOld := tx.State == "restored" || tx.State == "recovered"
	for _, c := range tx.Changes {
		old, e := s.wafCurrentMatches(c, false)
		if e != nil {
			return tx, false, e
		}
		next, e := s.wafCurrentMatches(c, true)
		if e != nil {
			return tx, false, e
		}
		if (wantNext && !next) || (wantOld && !old) || (!wantNext && !wantOld && !old && !next) {
			return tx, false, errors.New("入口被外部修改，拒绝恢复覆盖；原配置与事务证据保留")
		}
	}
	if tx.State == "committed" || tx.State == "recovered" {
		return tx, false, s.finishLoadBalanceTransaction(tx)
	}
	for i := len(tx.Changes) - 1; i >= 0; i-- {
		if e := wafApplyChange(tx.Changes[i], false); e != nil {
			return tx, false, e
		}
	}
	tx.State = "restored"
	return tx, true, s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx)
}
func (s *Service) verifyLoadBalanceLive(ctx context.Context, v loadBalanceEntry) error {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return nil
	}
	request, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:"+strconv.Itoa(v.Port)+loadBalanceProbePath(v.Domain), nil)
	if e != nil {
		return e
	}
	request.Host = v.Domain
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if v.Removed {
		if e != nil && ctx.Err() == nil && errors.Is(e, syscall.ECONNREFUSED) {
			return nil
		}
		if e != nil {
			return e
		}
		defer response.Body.Close()
		if response.StatusCode == 404 {
			return nil
		}
		return errors.New("已移除入口仍返回响应，未确认移除生效")
	}
	if e != nil {
		return e
	}
	defer response.Body.Close()
	b, e := io.ReadAll(io.LimitReader(response.Body, 257))
	if e != nil || response.StatusCode != 200 || len(b) > 256 || string(b) != loadBalanceFingerprint(v) {
		return errors.New("负载均衡真实入口指纹不匹配")
	}
	return nil
}
func (s *Service) reloadLoadBalance(ctx context.Context, nginx string) error {
	if _, e := s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf); e != nil {
		return e
	}
	g, e := s.captureWAFReloadGeneration(ctx, nginx)
	if e != nil {
		return e
	}
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); e != nil {
		return e
	}
	return waitWAFReloadGeneration(ctx, g)
}
func (s *Service) recoverLoadBalanceBeforeMutation(ctx context.Context, nginx string) error {
	tx, restored, e := s.restoreLoadBalanceTransaction()
	if e != nil || !restored {
		return e
	}
	if e = s.reloadLoadBalance(ctx, nginx); e != nil {
		return fmt.Errorf("原配置已恢复但重载未确认；事务保留：%w", e)
	}
	var old loadBalanceEntry
	if tx.Changes[1].OldExists {
		old, e = decodeLoadBalanceEntry(tx.Changes[1].OldData)
		if e != nil {
			return e
		}
		if old.Format > 0 {
			if e = s.verifyLoadBalanceLive(ctx, old); e != nil {
				return e
			}
		}
	}
	tx.State = "recovered"
	return s.finishLoadBalanceTransaction(tx)
}
func RecoverLoadBalanceConfiguration() error {
	s := nativeWAFService()
	if _, e := os.Lstat(s.loadBalancePendingPath()); errors.Is(e, os.ErrNotExist) {
		return nil
	}
	lock, e := s.lockWAFConfiguration()
	if e != nil {
		return e
	}
	defer lock.Close()
	tx, restored, e := s.restoreLoadBalanceTransaction()
	if e != nil || !restored {
		return e
	}
	nginx, e := s.nginxBinary()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, e = s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf); e != nil {
		return fmt.Errorf("负载均衡启动恢复后 Nginx 校验失败：%w", e)
	}
	tx.State = "recovered"
	return s.finishLoadBalanceTransaction(tx)
}
func (s *Service) moduleLoadBalance(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if action == "check-http" {
		return s.checkLoadBalanceHTTP(ctx, in)
	}
	if action != "run" && action != "recover" && action != "save" && action != "probe" && action != "remove" {
		return nil, errors.New("负载均衡操作无效")
	}
	if action != "run" && action != "recover" && (!core.ValidDomain(in.Domain) || strings.ToLower(in.Domain) != in.Domain) {
		return nil, errors.New("负载均衡域名须为规范小写域名")
	}
	lock, e := s.lockWAFConfiguration()
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if _, e := os.Lstat(s.wafPendingPath()); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("防火墙存在未完成事务，先恢复再修改入口")
	}
	unlock, e := s.lockRuntimeUse()
	if e != nil {
		return nil, e
	}
	defer unlock()
	nginx, e := s.nginxBinary()
	if e != nil {
		return nil, e
	}
	if action == "recover" {
		if e = s.recoverLoadBalanceBeforeMutation(ctx, nginx); e != nil {
			return nil, e
		}
	} else if _, e = os.Lstat(s.loadBalancePendingPath()); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("负载均衡存在未完成事务，先执行受控恢复；没有自动覆盖")
	}
	entries, e := s.loadBalanceEntries()
	if e != nil {
		return nil, e
	}
	if action == "run" || action == "recover" {
		health, err := s.loadBalanceHealthReports(entries, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		return map[string]any{"entries": entries, "count": len(entries), "pending": false, "transport": "HTTP loopback", "active_health_checks": len(health) > 0 && s.loadBalanceHealthInstalled(), "http_health": health, "automatic_traffic_changes": false}, nil
	}
	old, present, e := s.readLoadBalanceEntry(in.Domain)
	if e != nil {
		return nil, e
	}
	if action == "probe" {
		if !present || old.Removed {
			return nil, errors.New("入口不存在")
		}
		if old.Format > 0 {
			if e = s.verifyLoadBalanceLive(ctx, old); e != nil {
				return nil, e
			}
		}
		nodes := []any{}
		for _, n := range old.Nodes {
			dialer := net.Dialer{Timeout: time.Second}
			conn, e := dialer.DialContext(ctx, "tcp", n.Address)
			if conn != nil {
				conn.Close()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			nodes = append(nodes, map[string]any{"address": n.Address, "healthy": e == nil, "probe": "TCP connection only", "weight": n.Weight, "backup": n.Backup})
		}
		return map[string]any{"domain": old.Domain, "port": old.Port, "revision": old.Revision, "nodes": nodes, "entry_fingerprint_verified": old.Format > 0, "active_application_health_checks": old.HealthCheck != nil}, nil
	}
	wanted := int64(0)
	if present && !old.Removed {
		wanted = old.Revision
	}
	if in.ExpectedRevision != wanted {
		return nil, errors.New("入口修订号已改变，请刷新并选择当前记录，未覆盖")
	}
	next := loadBalanceEntry{Format: 1, Revision: old.Revision + 1, Domain: in.Domain, Port: in.Port, Nodes: in.Nodes, Sticky: in.Sticky, HealthCheck: in.HealthCheck, BackendTLS: in.BackendTLS}
	if next.BackendTLS != nil {
		next.Format = 2
	}
	if action == "remove" {
		if !present || old.Removed {
			return nil, errors.New("入口不存在")
		}
		next = old
		if next.Format == 0 {
			next.Format = 1
		}
		next.Revision++
		next.Removed = true
	} else {
		if next.BackendTLS != nil && s.loadBalanceHealthVersion() != "1.6.0" {
			return nil, errors.New("先更新已安装负载均衡到 v1.6.0，再显式启用 HTTPS 后端转发")
		}
		if next.HealthCheck != nil && !s.loadBalanceHealthInstalled() {
			return nil, errors.New("先更新已安装负载均衡到 v1.4.0，再启用持续 HTTP 检查")
		}
		if next.HealthCheck != nil && (next.HealthCheck.Scheme == "https" || next.HealthCheck.CheckPort != 0) && !s.loadBalanceHTTPSInstalled() {
			return nil, errors.New("先更新已安装负载均衡到 v1.5.0，再启用 HTTPS 检查")
		}
		if e := validateLoadBalanceEntry(next); e != nil {
			return nil, e
		}
		if e := validateLoadBalanceHealthBudget(entries, next); e != nil {
			return nil, e
		}
		if (!present || old.Removed) && len(entries) >= 64 {
			return nil, errors.New("最多 64 个活动入口")
		}
		for _, v := range entries {
			if v.Domain != next.Domain && v.Port == next.Port {
				return nil, errors.New("入口端口已由其他受管入口登记")
			}
		}
		if !present || old.Removed || old.Port != next.Port {
			listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", next.Port))
			if e != nil {
				return nil, errors.New("入口端口已占用")
			}
			listener.Close()
		}
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	rendered, e := s.renderLoadBalanceEntry(next)
	if e != nil {
		return nil, e
	}
	conf, meta := s.loadBalancePaths(in.Domain)
	for _, dir := range []string{filepath.Dir(conf), filepath.Dir(meta), filepath.Dir(s.loadBalancePendingPath())} {
		if e = s.wafOwnedDirectory(dir, true); e != nil {
			return nil, e
		}
	}
	tlsChange := old.BackendTLS != nil || next.BackendTLS != nil
	if tlsChange {
		if e = s.wafOwnedDirectory(filepath.Dir(s.loadBalanceCAPath(next.Domain)), true); e != nil {
			return nil, e
		}
	}
	if !present {
		if e = s.verifyLoadBalanceCA(loadBalanceEntry{Domain: next.Domain}); e != nil {
			return nil, e
		}
	}
	records, e := os.ReadDir(filepath.Dir(s.loadBalancePendingPath()))
	if e != nil || len(records) >= 512 {
		return nil, errors.New("负载均衡事务达到 512 份或不可读取；保留证据，未开始变更")
	}
	records, e = os.ReadDir(filepath.Dir(meta))
	if e != nil || (!present && len(records) >= 256) {
		return nil, errors.New("入口及已移除身份达到 256 项；拒绝遗忘旧修订号")
	}
	oldConf, e := backupFile(conf)
	if e != nil {
		return nil, e
	}
	oldMeta, e := backupFile(meta)
	if e != nil {
		return nil, e
	}
	// backupFile has a historical 0644 default for a missing leaf. A durable
	// transaction must encode absence with mode zero, not a fictitious file.
	if !oldConf.existed {
		oldConf.mode = 0
	}
	if !oldMeta.existed {
		oldMeta.mode = 0
	}
	nextMeta, _ := json.MarshalIndent(next, "", "  ")
	nextMeta = append(nextMeta, '\n')
	changes := []wafConfigChange{{Path: conf, OldData: oldConf.data, OldExists: oldConf.existed, OldMode: oldConf.mode, NextExists: !next.Removed}, {Path: meta, OldData: oldMeta.data, OldExists: oldMeta.existed, OldMode: oldMeta.mode, NextData: nextMeta, NextExists: true, NextMode: 0600}}
	if !next.Removed {
		changes[0].NextData = []byte(rendered)
		changes[0].NextMode = 0644
	}
	tx := loadBalanceTransaction{Format: 1, ID: core.ID(), Domain: next.Domain, State: "applying", CreatedAt: core.Now(), Changes: changes, Digests: map[string]string{}}
	if tlsChange {
		oldExists, oldData := loadBalanceCAState(old)
		nextExists, nextData := loadBalanceCAState(next)
		change := wafConfigChange{Path: s.loadBalanceCAPath(next.Domain), OldExists: oldExists, OldData: oldData, NextExists: nextExists, NextData: nextData}
		if oldExists {
			change.OldMode = 0600
		}
		if nextExists {
			change.NextMode = 0600
		}
		tx.Format = 2
		tx.Changes = append(tx.Changes, change)
		changes = tx.Changes
	}
	for _, c := range changes {
		tx.Digests[c.Path+":old"] = core.Hash(string(c.OldData))
		tx.Digests[c.Path+":next"] = core.Hash(string(c.NextData))
		match, e := s.wafCurrentMatches(c, false)
		if e != nil || !match {
			return nil, errors.New("入口备份期间发生外部修改，未开始变更")
		}
	}
	if e = s.writeLoadBalanceTransaction(filepath.Join(filepath.Dir(s.loadBalancePendingPath()), tx.ID+".json"), tx); e != nil {
		return nil, e
	}
	if e = s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); e != nil {
		return nil, e
	}
	rollback := func(cause error) (any, error) {
		rc, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if re := s.recoverLoadBalanceBeforeMutation(rc, nginx); re != nil {
			return nil, fmt.Errorf("%v；恢复未确认，请保留事务并检查：%w", cause, re)
		}
		return nil, fmt.Errorf("%v；原入口配置与清单已恢复，旧长请求不强制断开", cause)
	}
	for _, c := range changes {
		match, e := s.wafCurrentMatches(c, false)
		if e != nil || !match {
			return rollback(errors.New("入口写入前外部修改冲突"))
		}
		if e = wafApplyChange(c, true); e != nil {
			return rollback(e)
		}
	}
	if e = s.reloadLoadBalance(ctx, nginx); e != nil {
		return rollback(e)
	}
	if e = s.verifyLoadBalanceLive(ctx, next); e != nil {
		return rollback(e)
	}
	tx.State = "committed"
	if e = s.finishLoadBalanceTransaction(tx); e != nil {
		return nil, fmt.Errorf("入口已生效但事务归档未完成；不要重复提交，先核对并恢复：%w", e)
	}
	if action == "remove" {
		return map[string]any{"removed": next.Domain, "revision": next.Revision, "transaction_id": tx.ID, "website_files_deleted": false}, nil
	}
	return map[string]any{"domain": next.Domain, "port": next.Port, "nodes": next.Nodes, "sticky": next.Sticky, "revision": next.Revision, "transaction_id": tx.ID, "ok": true}, nil
}
