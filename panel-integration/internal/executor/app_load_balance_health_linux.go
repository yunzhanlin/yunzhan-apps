//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"local/panel/internal/core"
)

const lbHealthBodyLimit = 16 << 10

type loadBalanceHTTPNode struct {
	Address     string `json:"address"`
	State       string `json:"state"`
	Successes   int    `json:"successes"`
	Failures    int    `json:"failures"`
	LastSuccess bool   `json:"last_success"`
	Status      int    `json:"http_status"`
	Reason      string `json:"reason"`
	LatencyMS   int64  `json:"latency_ms"`
	CheckedAt   string `json:"checked_at"`
}
type loadBalanceHTTPTransition struct {
	Sequence int64  `json:"sequence"`
	Revision int64  `json:"revision"`
	Address  string `json:"address"`
	From     string `json:"from"`
	To       string `json:"to"`
	At       string `json:"at"`
}
type loadBalanceHTTPState struct {
	Format      int                         `json:"format"`
	Domain      string                      `json:"domain"`
	Revision    int64                       `json:"revision"`
	Fingerprint string                      `json:"fingerprint"`
	CheckedAt   string                      `json:"checked_at"`
	Sequence    int64                       `json:"sequence"`
	Nodes       []loadBalanceHTTPNode       `json:"nodes"`
	Transitions []loadBalanceHTTPTransition `json:"transitions"`
}

func validateLoadBalanceHealthBudget(entries []loadBalanceEntry, next loadBalanceEntry) error {
	count, nodes := 0, 0
	for _, v := range entries {
		if v.Domain == next.Domain {
			continue
		}
		if !v.Removed && v.HealthCheck != nil {
			count++
			nodes += len(v.Nodes)
		}
	}
	if !next.Removed && next.HealthCheck != nil {
		count++
		nodes += len(next.Nodes)
	}
	if count > 8 || nodes > 32 {
		return errors.New("持续 HTTP 检查最多启用 8 个入口、合计 32 个节点；全局并发最多 4")
	}
	return nil
}

func (s *Service) loadBalanceHealthVersion() string {
	path := filepath.Join(s.moduleDir("load-balance"), "installed.json")
	if s.wafOwnedDirectory(filepath.Dir(path), false) != nil {
		return ""
	}
	b, e := loadBalancePrivateRead(path, 32<<10)
	if e != nil {
		return ""
	}
	var v struct {
		ID          string         `json:"id"`
		Version     string         `json:"version"`
		InstalledAt string         `json:"installed_at"`
		UpdatedAt   string         `json:"updated_at,omitempty"`
		Settings    map[string]any `json:"settings"`
	}
	if decodeFTPPrivateJSON(b, &v) != nil || v.ID != "load-balance" || (v.Version != "1.4.0" && v.Version != "1.4.1" && v.Version != "1.5.0" && v.Version != "1.6.0") {
		return ""
	}
	if _, e := time.Parse(time.RFC3339, v.InstalledAt); e != nil {
		return ""
	}
	if v.UpdatedAt != "" {
		if _, e := time.Parse(time.RFC3339, v.UpdatedAt); e != nil {
			return ""
		}
	}
	return v.Version
}
func (s *Service) loadBalanceHTTPSInstalled() bool {
	version := s.loadBalanceHealthVersion()
	return version == "1.5.0" || version == "1.6.0"
}
func (s *Service) loadBalanceHealthInstalled() bool { return s.loadBalanceHealthVersion() != "" }
func (s *Service) loadBalanceHealthPath(domain string) string {
	return filepath.Join(s.moduleDir("load-balance"), "http-health", loadBalanceID(domain)+".json")
}
func lbHealthStateName(v string) bool {
	return v == "unknown" || v == "healthy" || v == "unhealthy"
}
func lbHealthReason(v string) bool {
	switch v {
	case "ok", "request_failed", "timeout", "status_mismatch", "body_incomplete", "body_too_large", "content_missing", "tls_validation_failed":
		return true
	}
	return false
}
func loadBalanceHealthAddress(v loadBalanceEntry, address string) (string, error) {
	ip, port, err := loadBalanceNodeAddress(address)
	if err != nil || v.HealthCheck == nil {
		return "", errors.New("检查节点或策略无效")
	}
	if v.HealthCheck.CheckPort != 0 {
		port = v.HealthCheck.CheckPort
	}
	if port < 1 || port > 65535 || (ip.IsLoopback() && (port == v.Port || port == 19100 || port == 19102 || port == 19080)) {
		return "", errors.New("检查端口不得指向入口或面板控制端口")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}
func (s *Service) readLoadBalanceHTTPState(v loadBalanceEntry, now time.Time) (*loadBalanceHTTPState, error) {
	path := s.loadBalanceHealthPath(v.Domain)
	if e := s.wafOwnedDirectory(filepath.Dir(path), false); errors.Is(e, os.ErrNotExist) {
		return nil, nil
	} else if e != nil {
		return nil, e
	}
	b, e := loadBalancePrivateRead(path, 32<<10)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var out loadBalanceHTTPState
	if decodeFTPPrivateJSON(b, &out) != nil || out.Format != 1 || out.Domain != v.Domain ||
		out.Revision < 1 || out.Revision >= 1<<60 || out.Sequence < 0 || out.Sequence >= 1<<60 ||
		len(out.Nodes) < 2 || len(out.Nodes) > 16 || len(out.Transitions) > 32 {
		return nil, errors.New("HTTP 检查记录内容损坏或身份不匹配；未覆盖")
	}
	prefix := loadBalanceID(out.Domain) + ":" + strconv.FormatInt(out.Revision, 10) + ":"
	if !strings.HasPrefix(out.Fingerprint, prefix) || len(out.Fingerprint) != len(prefix)+24 {
		return nil, errors.New("HTTP 检查配置指纹损坏；未覆盖")
	}
	if _, e := hex.DecodeString(strings.TrimPrefix(out.Fingerprint, prefix)); e != nil {
		return nil, errors.New("HTTP 检查配置指纹编码损坏；未覆盖")
	}
	at, e := time.Parse(time.RFC3339Nano, out.CheckedAt)
	if e != nil || at.After(now.Add(time.Minute)) {
		return nil, errors.New("HTTP 检查记录时间异常；未覆盖")
	}
	// Validate even a previous revision before it can be replaced. Corrupt
	// private state is not silently discarded as an ordinary revision change.
	seen := map[string]bool{}
	for _, n := range out.Nodes {
		_, _, addressErr := loadBalanceNodeAddress(n.Address)
		t, err := time.Parse(time.RFC3339Nano, n.CheckedAt)
		if addressErr != nil || seen[n.Address] || !lbHealthStateName(n.State) ||
			n.Successes < 0 || n.Successes > 10 || n.Failures < 0 || n.Failures > 10 ||
			(n.Successes > 0 && n.Failures > 0) || n.Status < 0 || n.Status > 599 ||
			!lbHealthReason(n.Reason) || n.LatencyMS < 0 || n.LatencyMS > 6000 ||
			(n.LastSuccess != (n.Reason == "ok")) ||
			(n.LastSuccess && (n.Successes < 1 || n.Failures != 0 || n.Status < 200 || n.Status > 299)) ||
			(!n.LastSuccess && (n.Failures < 1 || n.Successes != 0)) ||
			err != nil || t.After(at) || t.Before(at.Add(-time.Minute)) {
			return nil, errors.New("HTTP 节点检查记录损坏；未覆盖")
		}
		seen[n.Address] = true
	}
	var sequence int64
	for _, event := range out.Transitions {
		t, err := time.Parse(time.RFC3339Nano, event.At)
		if event.Sequence <= sequence || event.Sequence > out.Sequence || event.Revision < 1 ||
			event.Revision > out.Revision || !seen[event.Address] || !lbHealthStateName(event.From) ||
			!lbHealthStateName(event.To) || event.From == event.To || err != nil || t.After(at) {
			return nil, errors.New("HTTP 状态转换记录损坏；未覆盖")
		}
		sequence = event.Sequence
	}
	// A correctly formed previous revision is unknown for this configuration.
	// It must never contribute counters, healthy badges or recovery thresholds.
	if out.Revision != v.Revision {
		return nil, nil
	}
	if out.Fingerprint != loadBalanceFingerprint(v) {
		return nil, errors.New("同修订 HTTP 检查指纹与配置不符；未覆盖")
	}
	for i, n := range out.Nodes {
		if i >= len(v.Nodes) || n.Address != v.Nodes[i].Address {
			return nil, errors.New("HTTP 检查节点与同修订清单不一致；未覆盖")
		}
		if v.HealthCheck != nil && (n.Successes > v.HealthCheck.Successes || n.Failures > v.HealthCheck.Failures || (n.LastSuccess && n.Status != v.HealthCheck.ExpectedStatus)) {
			return nil, errors.New("HTTP 检查阈值或状态与策略不一致；未覆盖")
		}
	}
	if len(out.Nodes) != len(v.Nodes) {
		return nil, errors.New("HTTP 检查节点数量与清单不一致；未覆盖")
	}
	return &out, nil
}

func probeLoadBalanceHTTP(ctx context.Context, v loadBalanceEntry, address string) loadBalanceHTTPNode {
	start := time.Now()
	out := loadBalanceHTTPNode{Address: address, State: "unknown", Reason: "request_failed"}
	policy := v.HealthCheck
	target, targetErr := loadBalanceHealthAddress(v, address)
	if targetErr != nil {
		out.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return out
	}
	scheme := policy.Scheme
	if scheme == "" {
		scheme = "http"
	}
	roots, rootErr := core.LoadBalanceHealthRoots(policy.CAPEM)
	if rootErr != nil {
		out.Reason = "tls_validation_failed"
		out.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return out
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(policy.TimeoutMS)*time.Millisecond)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		MaxResponseHeaderBytes: 8192, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: v.Domain, RootCAs: roots},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(bounded, http.MethodGet, scheme+"://"+target+policy.Path, nil)
	if e == nil {
		request.Host = v.Domain
		request.Header.Set("User-Agent", "Yunzhan-HTTP-Health/1")
		var response *http.Response
		response, e = client.Do(request)
		if e == nil {
			out.Status = response.StatusCode
			if out.Status < 100 || out.Status > 599 {
				out.Status = 0
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, lbHealthBodyLimit+1))
			response.Body.Close()
			switch {
			case readErr != nil:
				out.Reason = "body_incomplete"
			case len(body) > lbHealthBodyLimit:
				out.Reason = "body_too_large"
			case response.StatusCode != policy.ExpectedStatus:
				out.Reason = "status_mismatch"
			case !bytes.Contains(body, []byte(policy.BodyContains)):
				out.Reason = "content_missing"
			default:
				out.LastSuccess, out.Reason = true, "ok"
			}
		}
	}
	var certificateError *tls.CertificateVerificationError
	if errors.As(e, &certificateError) {
		out.Reason = "tls_validation_failed"
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) {
		out.LastSuccess, out.Reason = false, "timeout"
	}
	out.LatencyMS = time.Since(start).Milliseconds()
	if out.LatencyMS > 6000 {
		out.LatencyMS = 6000
	}
	out.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return out
}

func advanceLoadBalanceHTTPState(v loadBalanceEntry, old *loadBalanceHTTPState, samples []loadBalanceHTTPNode, now time.Time) loadBalanceHTTPState {
	out := loadBalanceHTTPState{Format: 1, Domain: v.Domain, Revision: v.Revision, Fingerprint: loadBalanceFingerprint(v),
		CheckedAt: now.UTC().Format(time.RFC3339Nano), Nodes: samples, Transitions: []loadBalanceHTTPTransition{}}
	if old != nil {
		out.Sequence, out.Transitions = old.Sequence, append([]loadBalanceHTTPTransition{}, old.Transitions...)
	}
	for i := range out.Nodes {
		n := &out.Nodes[i]
		if old != nil {
			n.State, n.Successes, n.Failures = old.Nodes[i].State, old.Nodes[i].Successes, old.Nodes[i].Failures
		}
		before := n.State
		if n.LastSuccess {
			n.Failures = 0
			if n.Successes < v.HealthCheck.Successes {
				n.Successes++
			}
			if n.Successes >= v.HealthCheck.Successes {
				n.State = "healthy"
			}
		} else {
			n.Successes = 0
			if n.Failures < v.HealthCheck.Failures {
				n.Failures++
			}
			if n.Failures >= v.HealthCheck.Failures {
				n.State = "unhealthy"
			}
		}
		if before != n.State {
			out.Sequence++
			out.Transitions = append(out.Transitions, loadBalanceHTTPTransition{out.Sequence, v.Revision, n.Address, before, n.State, n.CheckedAt})
		}
	}
	if len(out.Transitions) > 32 {
		out.Transitions = out.Transitions[len(out.Transitions)-32:]
	}
	return out
}

func (s *Service) loadBalanceHealthLease() (*os.File, error) {
	dir := filepath.Dir(s.loadBalanceHealthPath("lease.example.test"))
	if e := s.wafOwnedDirectory(dir, true); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(dir, "worker.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("HTTP 检查锁身份或权限异常")
	}
	id, ok := st.Sys().(*syscall.Stat_t)
	if !ok || id.Uid != uint32(os.Geteuid()) || id.Nlink != 1 {
		f.Close()
		return nil, errors.New("HTTP 检查锁所有者或链接数异常")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (s *Service) loadBalanceHealthLeaseCurrent(f *os.File) error {
	path := filepath.Join(filepath.Dir(s.loadBalanceHealthPath("lease.example.test")), "worker.lock")
	if e := s.wafOwnedDirectory(filepath.Dir(path), false); e != nil {
		return e
	}
	open, e := f.Stat()
	if e != nil {
		return e
	}
	named, e := os.Lstat(path)
	if e != nil {
		return e
	}
	a, ok := open.Sys().(*syscall.Stat_t)
	b, namedOK := named.Sys().(*syscall.Stat_t)
	if !ok || !namedOK || !named.Mode().IsRegular() || named.Mode().Perm() != 0600 ||
		b.Uid != uint32(os.Geteuid()) || b.Nlink != 1 || a.Dev != b.Dev || a.Ino != b.Ino {
		return errors.New("HTTP 检查锁身份已改变，未执行或提交结果")
	}
	return nil
}

// No network requests occur while the shared Nginx/WAF mutation lock is held.
// One private cross-process lease covers both periodic and explicit checks.
func (s *Service) checkLoadBalanceHTTP(ctx context.Context, in core.AppModuleInput) (any, error) {
	if !core.ValidDomain(in.Domain) || in.ExpectedRevision < 1 {
		return nil, errors.New("先选择当前入口修订号")
	}
	if e := s.runLoadBalanceHTTPBatch(ctx, time.Now().UTC(), &in); e != nil {
		return nil, e
	}
	lock, e := s.lockWAFConfiguration()
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	v, present, e := s.readLoadBalanceEntry(in.Domain)
	if e != nil || !present || v.Removed || v.Revision != in.ExpectedRevision {
		return nil, errors.New("检查后入口修订号已改变，请刷新")
	}
	rows, e := s.loadBalanceHealthReports([]loadBalanceEntry{v}, time.Now().UTC())
	return map[string]any{"domain": v.Domain, "revision": v.Revision, "http_health": rows, "automatic_traffic_changes": false}, e
}

func (s *Service) runLoadBalanceHTTPBatch(ctx context.Context, now time.Time, selected *core.AppModuleInput) error {
	if !s.loadBalanceHealthInstalled() {
		if selected != nil {
			return errors.New("持续 HTTP 检查需要已安装负载均衡 v1.4.0")
		}
		return nil
	}
	lock, e := s.lockWAFConfiguration()
	if e != nil {
		return e
	}
	if _, e = os.Lstat(s.loadBalancePendingPath()); !errors.Is(e, os.ErrNotExist) {
		lock.Close()
		return errors.New("入口中断事务未恢复，暂停 HTTP 检查")
	}
	if _, e = os.Lstat(s.wafPendingPath()); !errors.Is(e, os.ErrNotExist) {
		lock.Close()
		return errors.New("WAF 中断事务未恢复，暂停 HTTP 检查")
	}
	entries, e := s.loadBalanceEntries()
	if e != nil {
		lock.Close()
		return e
	}
	due := []loadBalanceEntry{}
	oldStates := []*loadBalanceHTTPState{}
	enabled, nodes := 0, 0
	for _, v := range entries {
		if v.HealthCheck == nil {
			continue
		}
		if (v.HealthCheck.Scheme == "https" || v.HealthCheck.CheckPort != 0) && !s.loadBalanceHTTPSInstalled() {
			lock.Close()
			return errors.New("HTTPS 检查需要可信的负载均衡 v1.5.0 安装记录")
		}
		enabled++
		nodes += len(v.Nodes)
		if selected != nil && v.Domain != selected.Domain {
			continue
		}
		if selected != nil && v.Revision != selected.ExpectedRevision {
			lock.Close()
			return errors.New("入口修订号已改变，未开始检查")
		}
		old, err := s.readLoadBalanceHTTPState(v, now)
		if err != nil {
			lock.Close()
			return err
		}
		if selected == nil && old != nil {
			at, _ := time.Parse(time.RFC3339Nano, old.CheckedAt)
			if now.Before(at.Add(time.Duration(v.HealthCheck.Interval) * time.Second)) {
				continue
			}
		}
		due = append(due, v)
		oldStates = append(oldStates, old)
	}
	lock.Close()
	if enabled > 8 || nodes > 32 {
		return errors.New("HTTP 检查策略总量超限，未执行部分检查")
	}
	if len(due) == 0 {
		if selected != nil {
			return errors.New("所选入口未启用 HTTP 检查或已移除")
		}
		return nil
	}
	lease, e := s.loadBalanceHealthLease()
	if e != nil {
		return e
	}
	defer lease.Close()
	if e = s.loadBalanceHealthLeaseCurrent(lease); e != nil {
		return e
	}
	// Read snapshots again after acquiring the lease so an intervening complete
	// batch cannot be counted twice or have its counters overwritten.
	lock, e = s.lockWAFConfiguration()
	if e != nil {
		return e
	}
	for i, v := range due {
		if (v.HealthCheck.Scheme == "https" || v.HealthCheck.CheckPort != 0) && !s.loadBalanceHTTPSInstalled() {
			lock.Close()
			return errors.New("HTTPS 检查期间应用安装身份已改变，未提交结果")
		}
		current, present, err := s.readLoadBalanceEntry(v.Domain)
		if err != nil || !present || current.Removed || loadBalanceFingerprint(current) != loadBalanceFingerprint(v) {
			lock.Close()
			return errors.New("HTTP 检查开始前入口已改变，未继续")
		}
		oldStates[i], e = s.readLoadBalanceHTTPState(v, now)
		if e != nil {
			lock.Close()
			return e
		}
		if selected == nil && oldStates[i] != nil {
			at, _ := time.Parse(time.RFC3339Nano, oldStates[i].CheckedAt)
			if now.Before(at.Add(time.Duration(v.HealthCheck.Interval) * time.Second)) {
				lock.Close()
				return nil
			}
		}
	}
	lock.Close()
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	semaphore := make(chan struct{}, 4)
	samples := make([][]loadBalanceHTTPNode, len(due))
	var wg sync.WaitGroup
	for i, v := range due {
		samples[i] = make([]loadBalanceHTTPNode, len(v.Nodes))
		for j, node := range v.Nodes {
			wg.Add(1)
			go func(i, j int, v loadBalanceEntry, address string) {
				defer wg.Done()
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-bounded.Done():
					return
				}
				samples[i][j] = probeLoadBalanceHTTP(bounded, v, address)
			}(i, j, v, node.Address)
		}
	}
	wg.Wait()
	if e = bounded.Err(); e != nil {
		return e
	}
	lock, e = s.lockWAFConfiguration()
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = s.loadBalanceHealthLeaseCurrent(lease); e != nil {
		return e
	}
	if !s.loadBalanceHealthInstalled() {
		return errors.New("应用安装身份已改变，未提交检查结果")
	}
	for _, path := range []string{s.loadBalancePendingPath(), s.wafPendingPath()} {
		if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return errors.New("检查期间出现中断事务，未提交结果")
		}
	}
	completed := time.Now().UTC()
	// Validate ALL entries and previous records before publishing any result.
	for i, v := range due {
		if (v.HealthCheck.Scheme == "https" || v.HealthCheck.CheckPort != 0) && !s.loadBalanceHTTPSInstalled() {
			return errors.New("HTTPS 检查期间应用安装身份已改变，未提交结果")
		}
		current, present, err := s.readLoadBalanceEntry(v.Domain)
		if err != nil || !present || current.Removed || loadBalanceFingerprint(current) != loadBalanceFingerprint(v) {
			return errors.New("检查期间入口已改变，旧结果已丢弃")
		}
		previous, err := s.readLoadBalanceHTTPState(v, completed)
		if err != nil {
			return err
		}
		a, _ := json.Marshal(previous)
		b, _ := json.Marshal(oldStates[i])
		if !bytes.Equal(a, b) {
			return errors.New("检查记录并发改变，未覆盖")
		}
	}
	for i, v := range due {
		state := advanceLoadBalanceHTTPState(v, oldStates[i], samples[i], completed)
		if state.Sequence >= 1<<60 {
			return errors.New("HTTP 状态转换序号达到上限")
		}
		b, e := json.Marshal(state)
		if e != nil || len(b) > 32<<10 {
			return errors.New("HTTP 检查结果超限")
		}
		if e = atomicWrite(s.loadBalanceHealthPath(v.Domain), append(b, '\n'), 0600); e != nil {
			return e
		}
	}
	return nil
}

func (s *Service) loadBalanceHealthReports(entries []loadBalanceEntry, now time.Time) ([]map[string]any, error) {
	out := []map[string]any{}
	installed := s.loadBalanceHealthInstalled()
	s.lbHealthStatusMu.Lock()
	workerError := s.lbHealthWorkerError
	s.lbHealthStatusMu.Unlock()
	if !installed {
		workerError = "后台检查未运行：持续 HTTP 检查需要可信的负载均衡 v1.4.0 安装记录"
	}
	for _, v := range entries {
		if v.HealthCheck == nil {
			continue
		}
		state, e := s.readLoadBalanceHTTPState(v, now)
		if e != nil {
			return nil, e
		}
		for i, node := range v.Nodes {
			rowInstalled := installed
			row := map[string]any{"domain": v.Domain, "revision": v.Revision, "address": node.Address,
				"state": "unknown", "stale": true, "path": v.HealthCheck.Path, "interval": v.HealthCheck.Interval,
				"automatic_traffic_changes": false, "worker_error": workerError}
			row["scheme"] = "http"
			row["check_address"], _ = loadBalanceHealthAddress(v, node.Address)
			if v.HealthCheck.Scheme == "https" {
				row["scheme"] = "https"
				row["tls_verification"] = "系统信任库与入口域名"
				if v.HealthCheck.CAPEM != "" {
					row["tls_verification"] = "入口专用 CA 与入口域名"
				}
				if !s.loadBalanceHTTPSInstalled() {
					rowInstalled = false
					row["worker_error"] = "HTTPS 检查需要负载均衡 v1.5.0"
				}
			}
			if v.HealthCheck.CheckPort != 0 && !s.loadBalanceHTTPSInstalled() {
				rowInstalled = false
				row["worker_error"] = "独立检查端口需要负载均衡 v1.5.0"
			}
			if state != nil {
				n := state.Nodes[i]
				at, _ := time.Parse(time.RFC3339Nano, n.CheckedAt)
				stale := at.After(now.Add(time.Second)) || now.After(at.Add(time.Duration(2*v.HealthCheck.Interval)*time.Second+time.Duration(v.HealthCheck.TimeoutMS)*time.Millisecond))
				row["state"] = n.State
				if stale {
					row["state"] = "stale"
				}
				row["stale"], row["checked_at"], row["last_success"], row["http_status"] = stale, n.CheckedAt, n.LastSuccess, n.Status
				row["reason"], row["latency_ms"], row["failures"], row["successes"] = n.Reason, n.LatencyMS, n.Failures, n.Successes
				row["transitions"] = state.Transitions
			}
			if !rowInstalled {
				row["state"] = "inactive"
				row["stale"] = true
			}
			out = append(out, row)
		}
	}
	return out, nil
}

func (s *Service) runLoadBalanceHealthWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			e := s.runLoadBalanceHTTPBatch(ctx, now.UTC(), nil)
			s.lbHealthStatusMu.Lock()
			s.lbHealthWorkerError = ""
			if e != nil {
				s.lbHealthWorkerError = e.Error()
			}
			s.lbHealthStatusMu.Unlock()
		}
	}
}
