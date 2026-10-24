//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Opt-in only on the owned isolated guest. This drives a REAL native Nginx
// foreground process and actual HTTP/JSON log, not a fake command adapter.
// It cannot touch the existing site's Nginx config, service or history.
func TestStatisticsNativeNginxRequestIDsAndGzipReuse(t *testing.T) {
	if os.Getenv("PANEL_STATISTICS_NATIVE_NGINX_QA") != "1" {
		t.Skip("requires own zero-capability Linux native Nginx fixture")
	}
	host, e := os.ReadFile("/etc/hostname")
	name := strings.TrimSpace(string(host))
	if e != nil || name != "lima-panel-ids24hj-clean-ubuntu24" && name != "lima-panel-analytics23t-unit-debian13" || os.Geteuid() != 0 {
		t.Fatal("native fixture guest identity")
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil || !strings.Contains(string(status), "NoNewPrivs:\t1\n") {
		t.Fatal("native fixture requires actual NoNewPrivileges")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if !strings.Contains(string(status), key+":\t0000000000000000\n") {
			t.Fatal("native fixture capabilities widened", key)
		}
	}
	binary, e := os.ReadFile("/usr/sbin/nginx")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(binary)
	if len(os.Getenv("PANEL_STATISTICS_NATIVE_NGINX_SHA256")) != 64 || hex.EncodeToString(h[:]) != os.Getenv("PANEL_STATISTICS_NATIVE_NGINX_SHA256") {
		t.Fatal("native Nginx identity pin mismatch")
	}
	s, db, id, path, _ := statisticsReceiptFixture(t)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	format := statisticsNginxLegacyFormat
	temporary := ""
	for _, kind := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		temporary += fmt.Sprintf("%s_temp_path %s; ", kind, filepath.Join(dir, kind))
	}
	source := fmt.Sprintf("user root root; pid %s; error_log %s error; events { worker_connections 32; } http { %s log_format panel_site escape=json '%s'; access_log %s panel_site; server { listen 127.0.0.1:%d; server_name history.example; location / { return 503 'OWN-NATIVE-HISTORY'; } } }\n", filepath.Join(dir, "nginx.pid"), filepath.Join(dir, "nginx.error"), statisticsNginxPathMap+" "+statisticsNginxRefererMap+" "+temporary, format, path, port)
	updated, changed, formatErr := statisticsRequestIDNginxConfig([]byte(source))
	if formatErr != nil || !changed {
		t.Fatal("managed native format migration", formatErr)
	}
	if e = os.WriteFile(conf, updated, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	native := exec.CommandContext(ctx, "/usr/sbin/nginx", "-c", conf, "-p", dir, "-g", "daemon off; master_process off;")
	private, e := os.OpenFile(filepath.Join(dir, "native.private.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer private.Close()
	native.Stdout = private
	native.Stderr = private
	if e = native.Start(); e != nil {
		t.Fatal(e)
	}
	wait := make(chan error, 1)
	go func() { wait <- native.Wait(); close(wait) }()
	defer func() {
		if native.Process != nil {
			_ = native.Process.Signal(os.Interrupt)
			select {
			case <-wait:
			case <-time.After(2 * time.Second):
				_ = native.Process.Kill()
				<-wait
			}
		}
	}()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	ready := false
	for n := 0; n < 60; n++ {
		connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			connection.Close()
			ready = true
			break
		}
		select {
		case err := <-wait:
			for _, p := range []string{filepath.Join(dir, "native.private.log"), filepath.Join(dir, "nginx.error")} {
				if f, e := os.Open(p); e == nil {
					b, _ := io.ReadAll(io.LimitReader(f, 16384))
					f.Close()
					t.Log("private native fixture diagnostic", string(b))
				}
			}
			t.Fatal("real native Nginx exited", err)
		case <-time.After(25 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("real native Nginx did not become ready")
	}
	for _, target := range []string{"/same?password=native-query-secret", "/same?password=native-query-secret", "/third"} {
		request, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d%s", port, target), nil)
		request.Header.Set("User-Agent", "Examplebot/1.0 native-agent-secret")
		request.Header.Set("X-Request-Id", strings.Repeat("0", 32))
		reply, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(reply.Body, 1024))
		reply.Body.Close()
		if err != nil || reply.StatusCode != 503 || string(body) != "OWN-NATIVE-HISTORY" {
			t.Fatal("real native HTTP response", reply.StatusCode, err)
		}
	}
	// Native unbuffered access logging can complete immediately after headers;
	// wait for the actual three complete lines before invoking the collector.
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, err := os.ReadFile(path)
		if err == nil && strings.Count(string(b), "\n") == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real native request log incomplete", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	actualLog, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	ids := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(actualLog)), "\n") {
		var row analyticsAccess
		if json.Unmarshal([]byte(line), &row) != nil || !statisticsRequestID(row.RequestID) || row.RequestID == strings.Repeat("0", 32) || ids[row.RequestID] {
			t.Fatal("native request ID missing, duplicated or forged from client header")
		}
		ids[row.RequestID] = true
	}
	if len(ids) != 3 {
		t.Fatal("native ID population")
	}
	state := statisticsTestIngest(t, s, db, id, time.Now())
	report, e := statisticsHistoryReport(ctx, db, core.AppModuleInput{SiteID: id}, state, time.Now())
	if e != nil || report["requests"] != 3 || report["errors"] != 3 || report["bots"] != 3 || report["partial"] != false || state.Backlog != 0 {
		t.Fatal("native requests failed real durable aggregation", report, e)
	}
	latency := report["latency"].(analyticsLatencyReport)
	if !latency.QuantilesAvailable || latency.Samples != 3 || latency.Requests != 3 || latency.PopulationPartial || latency.P50 == nil || latency.P99 == nil || *latency.P50 > *latency.P99 {
		t.Fatal("actual native request timing did not enter exact aggregate", latency)
	}
	archive := path + "." + time.Now().UTC().Format("20060102-150405") + ".gz"
	statisticsArchiveTestWrite(t, archive, statisticsTestGzip(t, actualLog), time.Now())
	state = statisticsTestIngest(t, s, db, id, time.Now())
	if state.Duplicates != 3 || state.Compressed != 0 || state.VerifiedArchives != 1 || statisticsTestCount(t, db) != 3 || statisticsArchiveTestCount(t, db, "access_receipts") != 3 {
		t.Fatal("real native gzip replay counted requests twice", state)
	}
	db.Close()
	restarted := New(s.Config)
	after, e := restarted.openStatisticsHistorySchema(ctx, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer after.Close()
	state = statisticsTestIngest(t, restarted, after, id, time.Now())
	if statisticsTestCount(t, after) != 3 || state.Backlog != 0 {
		t.Fatal("native writer restart duplicated requests")
	}
	var secrets int
	if e = after.QueryRow("SELECT count(*) FROM access_rows WHERE instr(payload,'secret')>0").Scan(&secrets); e != nil || secrets != 0 {
		t.Fatal("native durable history leaked metadata", secrets, e)
	}
	t.Logf("PASS real pinned native Nginx %x, three actual HTTP503 including two identical paths, real unique native IDs unaffected by client request-ID header, full-CRC compressed-log replay dedup, private SQLite schema2 cursor/evidence and restart; isolated temporary listener/config only, not Main/authenticated installed API acceptance", h)
}
