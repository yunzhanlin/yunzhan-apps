//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Explicit compatibility-only native test. Existing signed executors are not
// replaced; this companion exercises the candidate's real shared handler.
func TestLoadBalanceNativeCandidateQA(t *testing.T) {
	if os.Getenv("PANEL_LB_NATIVE_QA") != "1" {
		t.Skip("explicit native QA gate required")
	}
	host, e := os.ReadFile("/etc/hostname")
	if e != nil || os.Geteuid() != 0 || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse unknown/main/non-root host")
	}
	b, e := exec.Command("/usr/bin/sqlite3", "/var/lib/panel/panel.db", "SELECT (SELECT count(*) FROM jobs WHERE state IN ('queued','running'))+(SELECT count(*) FROM runtime_jobs WHERE state IN ('queued','running'));").Output()
	if e != nil || strings.TrimSpace(string(b)) != "0" {
		t.Fatal("other active work; native mutation refused")
	}
	s := nativeWAFService()
	if !s.moduleInstalled("load-balance") {
		t.Fatal("test does not install absent applications")
	}
	if _, e = os.Lstat(s.loadBalancePendingPath()); !os.IsNotExist(e) {
		t.Fatal("existing pending transaction")
	}
	if _, e = s.loadBalanceEntries(); e != nil {
		t.Fatal(e)
	}
	stage := filepath.Join("/var/lib/panel-executor", "lb-native-candidate-"+core.ID())
	if e = os.Mkdir(stage, 0700); e != nil {
		t.Fatal(e)
	}
	domain := "lb-native-" + core.ID()[:12] + ".example.test"
	conf, meta := s.loadBalancePaths(domain)
	for _, p := range []string{conf, meta} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("QA target exists")
		}
	}
	native := func() map[string]string {
		out := map[string]string{}
		for _, unit := range []string{"nginx", "panel", "panel-executor", "panel-nfs-server", "panel-pure-ftpd", "panel-apache"} {
			b, e := exec.Command("/usr/bin/systemctl", "show", "-p", "MainPID,ExecMainStartTimestampMonotonic,ActiveState", unit).Output()
			if e != nil {
				t.Fatal(e)
			}
			out[unit] = string(b)
		}
		return out
	}
	before := native()
	results := []map[string]any{}
	passed := false
	cleaned := false
	report := func() {
		_ = moduleWrite(filepath.Join(stage, "acceptance.json"), map[string]any{"passed": passed && !t.Failed(), "source_candidate_only": true, "signed_release_acceptance": false, "not_direct_running_executor_API_business_acceptance": true, "architecture": runtime.GOARCH, "domain": domain, "http_results": results, "own_entry_removed": cleaned, "native_before": before, "native_after": native()})
		t.Log("load-balance native evidence retained at " + filepath.Join(stage, "acceptance.json"))
	}
	defer report()
	// Cleanup only the exact newly-created entry, via the same durable handler.
	defer func() {
		v, present, e := s.readLoadBalanceEntry(domain)
		if e != nil {
			t.Error("QA cleanup needs inspection", e)
			return
		}
		if present && !v.Removed {
			_, e = s.moduleLoadBalance(context.Background(), "remove", core.AppModuleInput{Domain: domain, ExpectedRevision: v.Revision})
			if e != nil {
				t.Error("QA cleanup retained entry and evidence", e)
				return
			}
		}
		_, e = os.Lstat(conf)
		cleaned = os.IsNotExist(e)
		if !cleaned {
			t.Error("QA entry configuration not removed")
		}
	}()
	var badA atomic.Bool
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if badA.Load() {
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, "backend-a")
	}))
	defer a.Close()
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend-b") }))
	defer backendB.Close()
	listener, e := net.Listen("tcp", "127.0.0.1:41973")
	if e != nil {
		t.Fatal("QA port unavailable", e)
	}
	listener.Close()
	in := core.AppModuleInput{Domain: domain, Port: 41973, Nodes: []core.AppUpstream{{Address: strings.TrimPrefix(a.URL, "http://"), Weight: 1}, {Address: strings.TrimPrefix(backendB.URL, "http://"), Weight: 3}}}
	save := func(label string) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		out, e := s.moduleLoadBalance(ctx, "save", in)
		if e != nil {
			t.Fatal(label, e)
		}
		in.ExpectedRevision = out.(map[string]any)["revision"].(int64)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	get := func(label string) string {
		request, e := http.NewRequest("GET", "http://127.0.0.1:41973/actual-business-request", nil)
		if e != nil {
			t.Fatal(e)
		}
		request.Host = domain
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(label, e)
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		if e != nil || response.StatusCode != 200 {
			t.Fatal(label, response.StatusCode, string(body), e)
		}
		results = append(results, map[string]any{"phase": label, "status": response.StatusCode, "backend": string(body), "expected_revision": in.ExpectedRevision})
		return string(body)
	}
	save("weighted create")
	counts := map[string]int{}
	for i := 0; i < 48; i++ {
		counts[get("weighted")]++
	}
	if counts["backend-a"] < 6 || counts["backend-a"] > 18 || counts["backend-b"] < 30 || counts["backend-b"] > 42 {
		t.Fatal("weighted distribution missing", counts)
	}
	in.Sticky = true
	save("sticky update")
	same := ""
	for i := 0; i < 12; i++ {
		got := get("ip sticky")
		if same == "" {
			same = got
		}
		if got != same {
			t.Fatal("same loopback client changed sticky backend")
		}
	}
	in.Sticky = false
	in.Nodes[0].Weight = 1
	in.Nodes[1].Weight = 1
	in.Nodes[1].Backup = true
	save("backup update")
	for i := 0; i < 12; i++ {
		if got := get("primary before failure"); got != "backend-a" {
			t.Fatal("backup used before primary failure", got)
		}
	}
	badA.Store(true)
	for i := 0; i < 12; i++ {
		if got := get("503 fallback"); got != "backend-b" {
			t.Fatal("primary failure not routed to backup", got)
		}
	}
	probe, e := s.moduleLoadBalance(context.Background(), "probe", core.AppModuleInput{Domain: domain})
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range probe.(map[string]any)["nodes"].([]any) {
		if !row.(map[string]any)["healthy"].(bool) || row.(map[string]any)["probe"] != "TCP connection only" {
			t.Fatal("application 503 must not be mislabeled as failed TCP probe", row)
		}
	}
	beforeFiles := lbFiles(t, s, domain)
	stale := in
	stale.ExpectedRevision = 1
	if _, e = s.moduleLoadBalance(context.Background(), "save", stale); e == nil {
		t.Fatal("stale business update accepted")
	}
	lbAssertFiles(t, s, domain, beforeFiles)
	// Own-file manual drift is rejected without executing nginx or losing edits.
	if e = atomicWrite(conf, append(append([]byte{}, beforeFiles[conf]...), []byte("# qa external edit\n")...), 0644); e != nil {
		t.Fatal(e)
	}
	edited := lbFiles(t, s, domain)
	if _, e = s.moduleLoadBalance(context.Background(), "save", in); e == nil {
		t.Fatal("external drift accepted")
	}
	lbAssertFiles(t, s, domain, edited)
	if e = atomicWrite(conf, beforeFiles[conf], 0644); e != nil {
		t.Fatal(e)
	}
	// Real hot rollback: syntax validation is faulted once, restoration validates
	// and reloads actual selected Nginx and proves the original entry fingerprint.
	originalRun := s.Config.Run
	checks := 0
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "-t" {
			checks++
			if checks == 1 {
				return "", errors.New("QA injected pre-reload syntax failure")
			}
		}
		return originalRun(ctx, name, args...)
	}
	failed := in
	failed.Nodes = append([]core.AppUpstream{}, in.Nodes...)
	failed.Nodes[0].Weight = 4
	_, e = s.moduleLoadBalance(context.Background(), "save", failed)
	s.Config.Run = originalRun
	if e == nil || checks != 2 || !strings.Contains(e.Error(), "已恢复") {
		t.Fatal("real rollback not confirmed", e, checks)
	}
	lbAssertFiles(t, s, domain, beforeFiles)
	removed, e := s.moduleLoadBalance(context.Background(), "remove", core.AppModuleInput{Domain: domain, ExpectedRevision: in.ExpectedRevision})
	if e != nil {
		t.Fatal(e)
	}
	oldRevision := removed.(map[string]any)["revision"].(int64)
	badA.Store(false)
	in.ExpectedRevision = 0
	save("recreate")
	if in.ExpectedRevision != oldRevision+1 {
		t.Fatal("recreate forgot tombstone revision")
	}
	if _, e = s.moduleLoadBalance(context.Background(), "remove", core.AppModuleInput{Domain: domain, ExpectedRevision: 1}); e == nil {
		t.Fatal("stale ABA removal accepted")
	}
	oldBytes, _ := json.Marshal(before)
	newBytes, _ := json.Marshal(native())
	if string(oldBytes) != string(newBytes) {
		t.Fatal("unrelated native service identity changed")
	}
	passed = true
}
