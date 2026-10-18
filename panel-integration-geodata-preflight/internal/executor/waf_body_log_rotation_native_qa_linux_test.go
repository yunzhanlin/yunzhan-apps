//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Called only by the isolated, native-engine managed-site QA gate. Preserve
// original dormant evidence by rename, never truncate or delete it. All test
// logs/results remain recoverable beside the original configuration backup.
func wafPrepareAutomaticRotationQALogs(s *Service, backup string) (func() error, error) {
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		return nil, err
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil || cfg.Body != nil || cfg.BodyLogRotation != nil || cfg.BodyLogRetention != nil {
		return nil, errors.New("refuse to displace active or previously configured body evidence")
	}
	if _, err := s.wafBodyLogArchives(); err != nil {
		return nil, err
	}
	base := filepath.Join(backup, "automatic-rotation-native-qa")
	if err := os.Mkdir(base, 0700); err != nil {
		return nil, err
	}
	type entry struct {
		path, old string
		info      os.FileInfo
		sha       string
	}
	entries := []entry{}
	for i, path := range []string{s.systemPath(wafBodyLogPath), s.wafBodyLogArchiveDirectory(), s.wafBodyRotationPath(), s.wafBodyRetentionPath()} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			entries = append(entries, entry{path: path, old: filepath.Join(base, fmt.Sprintf("original-%d", i))})
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("foreign original log evidence")
		}
		sha := ""
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			sha = core.Hash(string(data))
		}
		entries = append(entries, entry{path: path, old: filepath.Join(base, fmt.Sprintf("original-%d", i)), info: info, sha: sha})
	}
	moved := 0
	for i, e := range entries {
		if e.info != nil {
			if err := os.Rename(e.path, e.old); err != nil {
				for _, previous := range entries[:moved] {
					if previous.info != nil {
						_ = os.Rename(previous.old, previous.path)
					}
				}
				return nil, err
			}
		}
		moved = i + 1
	}
	return func() error {
		for i, e := range entries {
			if _, err := os.Lstat(e.path); err == nil {
				if err := os.Rename(e.path, filepath.Join(base, fmt.Sprintf("result-%d", i))); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if e.info != nil {
				if err := os.Rename(e.old, e.path); err != nil {
					return err
				}
				actual, err := os.Lstat(e.path)
				if err != nil || !os.SameFile(e.info, actual) || actual.Mode() != e.info.Mode() {
					return errors.New("original evidence inode or permissions changed")
				}
				if e.sha != "" {
					data, err := os.ReadFile(e.path)
					if err != nil || core.Hash(string(data)) != e.sha {
						return errors.New("original numerical log bytes changed")
					}
				}
			}
		}
		return nil
	}, nil
}

// Only the explicitly gated native QA calls this. Retry solely the typed
// pre-mutation lock-busy error, never a reload/recovery/commit failure.
func wafNativeRetryLockBusy(ctx context.Context, operation func() error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := operation()
		if !errors.Is(err, errWAFConfigurationBusy) {
			return err
		}
		timer := time.NewTimer(150 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func wafAutomaticRotationManagedNativeQA(t *testing.T, s *Service, cfg core.WAFConfig, site, domain, backup string) {
	t.Helper()
	cfg.Body.Sites[0].Policy.Mode = "block"
	cfg.TrustedProxy = &core.WAFTrustedProxyConfig{Enabled: true, Header: "X-Forwarded-For", TrustedCIDRs: []string{"127.0.0.1/32"}, AcknowledgeHeaderControl: true}
	cfg.BodyLogRotation = &core.WAFBodyLogRotationConfig{Enabled: true, RotateMiB: 1, MaxAgeMinutes: 10}
	for _, ip := range []string{"203.0.113.40", "2001:db8::40"} {
		cfg.Policy.Lists["ip_deny"] = append(cfg.Policy.Lists["ip_deny"], core.WAFEntry{ID: core.ID(), Value: ip, SiteID: site})
	}
	if err := wafNativeRetryLockBusy(context.Background(), func() error {
		return s.applyWAF(context.Background(), core.WAFSettings(cfg), false, func(string) {})
	}); err != nil {
		t.Fatal("verified native automatic-rotation apply", err)
	}
	m, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = core.DecodeWAFConfig(m.Settings)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		Name         string
		Status       int
		Peer, Header string
	}
	results := []outcome{}
	visit := func(name, peer, ip, body string, want int) {
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(peer)}, Timeout: 3 * time.Second}).DialContext}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
		req, _ := http.NewRequest("POST", "http://127.0.0.1:19101/probe", strings.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(name, err)
		}
		_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		res.Body.Close()
		if err != nil || res.StatusCode != want {
			t.Fatalf("joint native identity/body %s: %d expected %d: %v", name, res.StatusCode, want, err)
		}
		results = append(results, outcome{name, res.StatusCode, peer, ip})
	}
	ordinary := `{"term":"ordinary"}`
	attack := `{"term":"<script>alert('owned_rotation_private')</script>"}`
	visit("trusted-ipv4-deny", "127.0.0.1", "203.0.113.40", ordinary, 403)
	visit("trusted-ipv6-deny", "127.0.0.1", "2001:db8::40", ordinary, 403)
	visit("untrusted-spoof-rejected", "127.0.0.2", "203.0.113.40", ordinary, 200)
	visit("trusted-body-enforced", "127.0.0.1", "203.0.113.42", attack, 403)
	before, err := os.Stat(wafBodyLogPath)
	if err != nil || before.Size() == 0 {
		t.Fatal("actual engine emitted no current numerical records", err)
	}
	nativeBefore := wafQANativeProtectedSnapshot(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.runWAFBodyLogRotationOnce(context.Background(), now); err != nil {
		t.Fatal("real guarded first scheduler cycle", err)
	}
	first, _, err := s.readWAFBodyRotationRecord()
	if err != nil || first.State != "idle" {
		t.Fatal(first, err)
	}
	// Fill only our freshly created log through real native HTTP requests;
	// never pad or synthesize numerical rows and never touch original history.
	trafficCtx, trafficCancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer trafficCancel()
	loadTransport := &http.Transport{Proxy: nil, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4}
	defer loadTransport.CloseIdleConnections()
	loadClient := &http.Client{Transport: loadTransport, Timeout: 5 * time.Second}
	loadRequests := 0
	for loadRequests < 10000 {
		info, err := os.Stat(wafBodyLogPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() >= 1<<20 {
			break
		}
		failures := make(chan error, 32)
		limit := make(chan struct{}, 4)
		var group sync.WaitGroup
		for i := 0; i < 32; i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				limit <- struct{}{}
				defer func() { <-limit }()
				req, _ := http.NewRequestWithContext(trafficCtx, "POST", "http://127.0.0.1:19101/probe", strings.NewReader(attack))
				req.Host = domain
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Forwarded-For", "203.0.113.42")
				res, err := loadClient.Do(req)
				if err != nil {
					failures <- err
					return
				}
				_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
				res.Body.Close()
				if err != nil || res.StatusCode != 403 {
					failures <- fmt.Errorf("native load HTTP %d: %v", res.StatusCode, err)
				}
			}()
		}
		group.Wait()
		close(failures)
		for err := range failures {
			t.Fatal("actual local native traffic", err)
		}
		loadRequests += 32
	}
	original, err := os.ReadFile(wafBodyLogPath)
	if err != nil || len(original) < 1<<20 || len(original) > 28<<20 {
		t.Fatal("actual native traffic did not produce bounded size trigger", len(original), err)
	}
	if bytes.Contains(original, []byte("owned_rotation_private")) {
		t.Fatal("private request leaked to numerical log")
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); s.runWAFBodyLogRotationWorker(workerCtx) }()
	defer func() {
		workerCancel()
		select {
		case <-workerDone:
		case <-time.After(5 * time.Second):
			t.Error("automatic worker did not stop before log restoration")
		}
	}()
	var completed wafBodyRotationRecord
	for deadline := time.Now().Add(20 * time.Second); ; {
		completed, _, err = s.readWAFBodyRotationRecord()
		if err == nil && completed.State == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real-clock worker startup did not complete size rotation", completed, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || completed.State != "completed" || completed.Archive == nil || completed.Archive.SHA256 != core.Hash(string(original)) || len(completed.History) != 1 {
		t.Fatal("full native snapshot not verified", completed, err)
	}
	after, err := os.Stat(wafBodyLogPath)
	if err != nil || !os.SameFile(before, after) || after.Size() != 0 || after.Mode() != before.Mode() {
		t.Fatal("native writer inode not preserved", err)
	}
	// Only our newly-owned scheduler record is expected to change here. Keep
	// the shared native preservation guard unchanged for every other path.
	var oldNative, nextNative map[string]string
	if json.Unmarshal([]byte(nativeBefore), &oldNative) != nil || json.Unmarshal([]byte(wafQANativeProtectedSnapshot(t)), &nextNative) != nil {
		t.Fatal("invalid native preservation snapshot")
	}
	recordBytes, err := os.ReadFile(s.wafBodyRotationPath())
	if err != nil || nextNative[s.wafBodyRotationPath()] != core.Hash(string(recordBytes)) {
		t.Fatal("expected rotation audit digest differs from actual owned record", err)
	}
	delete(oldNative, s.wafBodyRotationPath())
	delete(nextNative, s.wafBodyRotationPath())
	oldJSON, _ := json.Marshal(oldNative)
	nextJSON, _ := json.Marshal(nextNative)
	if changed, okay := wafQANativeChanges(string(oldJSON), string(nextJSON)); !okay {
		t.Fatal("automatic rotation mutated native/config state", changed)
	}
	visit("native-writer-resumed-after-rotation", "127.0.0.1", "203.0.113.42", attack, 403)
	resumed, err := os.ReadFile(wafBodyLogPath)
	if err != nil || len(resumed) == 0 || bytes.Contains(resumed, []byte("owned_rotation_private")) {
		t.Fatal("native writer did not resume privately", err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(resumed), []byte{'\n'}) {
		if _, ok := parseWAFBodyEvent(line); !ok {
			t.Fatal("non-numeric native event after automatic rotation")
		}
	}
	current, err := os.Stat(wafBodyLogPath)
	if err != nil || !os.SameFile(before, current) {
		t.Fatal("native descriptor identity changed", err)
	}
	var tick wafBodyRotationRecord
	for deadline := time.Now().Add(80 * time.Second); ; {
		tick, _, err = s.readWAFBodyRotationRecord()
		checked, _ := time.Parse(time.RFC3339, tick.CheckedAt)
		finished, _ := time.Parse(time.RFC3339, completed.LastRotationAt)
		if err == nil && tick.State == "idle" && checked.Sub(finished) >= 55*time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real one-minute worker tick not observed", tick, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if tick.WindowStartedAt != completed.WindowStartedAt || len(tick.History) != 1 {
		t.Fatal("real minute tick reset durable window or repeated truncate", tick)
	}
	workerCancel()
	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("parent worker did not retire before independent process verification")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	processCtx, processCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer processCancel()
	selfSHA, err := wafNativeFileSHA(processCtx, self, 96<<20)
	if err != nil {
		t.Fatal(err)
	}
	currentBytes, err := os.ReadFile(wafBodyLogPath)
	if err != nil {
		t.Fatal(err)
	}
	request := wafAutoWindowProcessRequest{ParentPID: os.Getpid(), ExecutableSHA: selfSHA, SiteID: site, Revision: cfg.Policy.Revision, WindowStartedAt: completed.WindowStartedAt, LogSHA: core.Hash(string(currentBytes)), LogInode: current.Sys().(*syscall.Stat_t).Ino, Nonce: core.ID()}
	processBase := filepath.Join(backup, "automatic-rotation-native-qa")
	if err := moduleWrite(filepath.Join(processBase, "window-process-request.json"), request); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(processCtx, self, "-test.run", "^TestWAFBodyAutomaticRotationFreshProcessNativeQA$", "-test.v", "-test.timeout", "20s")
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PANEL_WAF_AUTO_WINDOW_QA_ID=" + filepath.Base(backup)}
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("independent process window verification failed: %v\n%s", err, output)
	}
	processData, err := os.ReadFile(filepath.Join(processBase, "window-process-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var processResult wafAutoWindowProcessResult
	if json.Unmarshal(processData, &processResult) != nil || !processResult.Passed || processResult.ParentPID != os.Getpid() || processResult.ChildPID == os.Getpid() || processResult.ExecutableSHA != selfSHA || processResult.Nonce != request.Nonce || processResult.WindowStartedAt != completed.WindowStartedAt {
		t.Fatal("independent PID proof not bound to this fixture", processResult)
	}
	idle, _, err := s.readWAFBodyRotationRecord()
	if err != nil || idle.State != "idle" || idle.WindowStartedAt != completed.WindowStartedAt || len(idle.History) != 1 {
		t.Fatal("fresh process reset window or repeated truncate", idle, err)
	}
	stat := current.Sys().(*syscall.Stat_t)
	report := map[string]any{"passed": true, "source_candidate_only": true, "direct_signed_API_business_proof": false, "actual_VM_cold_boot_verified": false, "explicit_cycle_clock_test": false, "production_worker_implementation_real_clock_verified": true, "actual_native_load_requests_all_HTTP403": loadRequests, "native_generated_log_bytes_before_rotation": len(original), "actual_minute_tick_record": tick, "real_guarded_scheduler_and_native_writer_verified": true, "trusted_proxy_and_native_body_jointly_enabled": true, "requests": results, "original_numerical_snapshot_sha256": core.Hash(string(original)), "snapshot_sha256": completed.Archive.SHA256, "active_inode": stat.Ino, "same_inode": true, "native_writer_resumed": true, "no_native_reload_or_config_changes_during_rotation": true, "process_restart_window_preserved": true, "actual_fresh_PID_verified": true, "independent_process_result": processResult, "original_dormant_logs_preserved_by_rename_and_restored_after_config_restore": true}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(backup, "automatic-rotation-native-qa", "acceptance.json")
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("guarded automatic rotation native evidence retained at", path)
}

type wafAutoWindowProcessRequest struct {
	ParentPID       int    `json:"parent_pid"`
	ExecutableSHA   string `json:"executable_sha256"`
	SiteID          string `json:"site_id"`
	Revision        int64  `json:"revision"`
	WindowStartedAt string `json:"window_started_at"`
	LogSHA          string `json:"log_sha256"`
	LogInode        uint64 `json:"log_inode"`
	Nonce           string `json:"nonce"`
}
type wafAutoWindowProcessResult struct {
	Passed              bool   `json:"passed"`
	ParentPID           int    `json:"parent_pid"`
	ChildPID            int    `json:"child_pid"`
	ExecutableSHA       string `json:"executable_sha256"`
	Nonce               string `json:"nonce"`
	WindowStartedAt     string `json:"window_started_at"`
	CurrentLogUnchanged bool   `json:"current_log_unchanged"`
}

// Test-only child entrypoint, not a production command or environment knob.
// It can update only an already-created, digest-bound idle QA scheduler record.
func TestWAFBodyAutomaticRotationFreshProcessNativeQA(t *testing.T) {
	id := os.Getenv("PANEL_WAF_AUTO_WINDOW_QA_ID")
	if id == "" {
		t.Skip("explicit isolated native parent/child gate required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse main/foreign native child gate")
	}
	base := filepath.Join("/etc/panel/security-apps/waf-backups", id, "automatic-rotation-native-qa")
	path := filepath.Join(base, "window-process-request.json")
	if err := ownedRuntimePath(base, true); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("unsafe child authorization record")
	}
	var req wafAutoWindowProcessRequest
	d := json.NewDecoder(io.LimitReader(f, 16<<10))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || req.ParentPID != os.Getppid() || req.ParentPID == os.Getpid() || !core.ValidID(req.SiteID) || !core.ValidID(req.Nonce) || !wafLogDigestValid(req.ExecutableSHA) || !wafLogDigestValid(req.LogSHA) {
		t.Fatal("unbound child authorization")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sha, err := wafNativeFileSHA(ctx, self, 96<<20)
	if err != nil || sha != req.ExecutableSHA {
		t.Fatal("different child executable", err)
	}
	s := nativeWAFService()
	m, err := s.readSoftwareManifest("nginx-waf")
	if err != nil || m.Version != core.WAFVersion {
		t.Fatal("unexpected actual native QA version", err)
	}
	cfg, err := core.DecodeWAFConfig(m.Settings)
	if err != nil || cfg.Body == nil || len(cfg.Body.Sites) != 1 || cfg.Body.Sites[0].SiteID != req.SiteID || cfg.Policy.Revision != req.Revision || cfg.BodyLogRotation == nil || !cfg.BodyLogRotation.Enabled {
		t.Fatal("unexpected native QA scope", err)
	}
	record, _, err := s.readWAFBodyRotationRecord()
	start, parseErr := time.Parse(time.RFC3339, record.WindowStartedAt)
	if err != nil || parseErr != nil || record.State != "idle" || record.WindowStartedAt != req.WindowStartedAt || len(record.History) != 1 || time.Since(start) < 0 || time.Since(start) > 2*time.Minute {
		t.Fatal("child does not own a current idle window", record, err)
	}
	log, err := s.openWAFBodyLog(false, false)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := log.Stat()
	data, readErr := io.ReadAll(log)
	log.Close()
	if readErr != nil || info == nil || info.Size() >= int64(cfg.BodyLogRotation.RotateMiB)<<20 || info.Sys().(*syscall.Stat_t).Ino != req.LogInode || core.Hash(string(data)) != req.LogSHA {
		t.Fatal("child live evidence changed or due; never authorize a truncate")
	}
	history, _ := json.Marshal(record.History)
	if err := s.runWAFBodyLogRotationOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	after, _, err := s.readWAFBodyRotationRecord()
	nextHistory, _ := json.Marshal(after.History)
	next, readErr := os.ReadFile(wafBodyLogPath)
	nextInfo, statErr := os.Stat(wafBodyLogPath)
	if err != nil || readErr != nil || statErr != nil || after.State != "idle" || after.WindowStartedAt != record.WindowStartedAt || !bytes.Equal(history, nextHistory) || !bytes.Equal(data, next) || !os.SameFile(info, nextInfo) {
		t.Fatal("fresh PID reset window, history or current log", err)
	}
	result := wafAutoWindowProcessResult{Passed: true, ParentPID: req.ParentPID, ChildPID: os.Getpid(), ExecutableSHA: sha, Nonce: req.Nonce, WindowStartedAt: after.WindowStartedAt, CurrentLogUnchanged: true}
	if err := moduleWrite(filepath.Join(base, "window-process-result.json"), result); err != nil {
		t.Fatal(err)
	}
}
