//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestApacheBodyEventsBoundedFileSnapshotAndRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	valid := apacheBodyNumericEventFixture()
	data := valid + "\n" + valid + "\n" + strings.TrimSuffix(valid, "}") + `,"cookie":"private-reader-secret"}` + "\n" + valid
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	page, err := readApacheBodyEventsFile(context.Background(), f)
	if err != nil || !page.Available || !page.Partial || page.Rejected != 2 || len(page.Events) != 2 || page.LogBytes != int64(len(data)) {
		t.Fatal(page, err)
	}
	if encoded, _ := json.Marshal(page); strings.Contains(string(encoded), "private-reader-secret") {
		t.Fatal("rejected line leaked")
	}
	hold, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(hold.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if out, err := readApacheBodyEventsFile(context.Background(), f); err == nil || out.Available || len(out.Events) > 0 {
		t.Fatal("busy writer returned an empty verified report", out, err)
	}
	hold.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := readApacheBodyEventsFile(ctx, f); !errors.Is(err, context.Canceled) || out.Available || len(out.Events) != 0 {
		t.Fatal("canceled snapshot returned stale events", out, err)
	}
	if current, err := os.ReadFile(path); err != nil || string(current) != data {
		t.Fatal("observation modified original bytes", err)
	}
	for _, scenario := range []string{"event-count", "tail-byte-budget"} {
		path := filepath.Join(t.TempDir(), "events.log")
		payload := strings.Repeat(valid+"\n", 5001)
		if scenario == "tail-byte-budget" {
			payload = strings.Repeat(strings.Repeat("x", 512)+"\n", 10000) + valid + "\n"
		}
		if err := os.WriteFile(path, []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		out, err := readApacheBodyEventsFile(context.Background(), file)
		file.Close()
		want := 5000
		if scenario == "tail-byte-budget" {
			want = 1
		}
		if err != nil || !out.Partial || len(out.Events) != want {
			t.Fatal("event/byte budget not enforced", scenario, len(out.Events), out.Partial, err)
		}
	}
}

func TestApacheBodyEventsNativeReadonlyFixedAuthority(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_EVENTS_NATIVE") != "1" {
		t.Skip("explicit Root READ_SEARCH-only private fixed-directory fixture required")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "0000000000000004" || identity["CapBnd"] != "0000000000000004" || identity["NoNewPrivs"] != "1" {
		t.Fatal("numeric reader obtained unexpected native authority", identity)
	}
	const fixture = "/run/panel-apache-events24ana"
	var scenario struct {
		Name      string `json:"name"`
		Status    int    `json:"status"`
		Available bool   `json:"available"`
	}
	data, err := os.ReadFile(filepath.Join(fixture, "case.json"))
	if err != nil || json.Unmarshal(data, &scenario) != nil || scenario.Name == "" {
		t.Fatal("private native case identity missing", err)
	}
	s := New(Config{SystemRoot: "/"})
	mux := http.NewServeMux()
	s.apacheBodyReportRoutes(mux)
	query := "?from=2026-10-10T22:00:00Z&to=2026-10-11T02:00:00Z&limit=1&page=1"
	request := func(ctx context.Context, query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/v1/software/apache-waf/body-report"+query, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	w := request(context.Background(), query)
	if w.Code != scenario.Status || strings.Contains(w.Body.String(), "private-native-secret") {
		t.Fatal("actual native authority / privacy result changed", scenario.Name, w.Code, w.Body.String())
	}
	if w.Code == 200 {
		var out core.ApacheBodyReport
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Available != scenario.Available || !out.BestEffort || out.MaxBytes != 32<<20 || out.Counting != core.ApacheBodyCountingContract || out.Scope != core.ApacheBodyReportScope {
			t.Fatal("actual numerical route schema changed", w.Body.String())
		}
		if scenario.Available && (out.Matches != 2 || len(out.Events) != 1 || !out.Partial || out.Rejected != 2 || out.Scanned != 2) {
			t.Fatal("actual numeric fixture report not complete and bounded", out)
		}
		if scenario.Available {
			hold, err := os.Open(apacheBodyMetadataLog)
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Flock(int(hold.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			busy := request(context.Background(), query)
			hold.Close()
			if busy.Code != 503 {
				t.Fatal("actual lock contention appeared as zero records", busy.Code)
			}
		}
	}
	if invalid := request(context.Background(), "?path=/etc/shadow"); invalid.Code != 400 {
		t.Fatal("native reader accepted arbitrary path", invalid.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if canceled := request(ctx, query); canceled.Code != 503 {
		t.Fatal("canceled actual read appeared complete", canceled.Code)
	}
	proof, err := json.MarshalIndent(map[string]any{"passed": true, "case": scenario.Name, "actual_native_status": w.Code, "readonly_root_capability_mask": "0x4", "supervisor_identity": identity, "arbitrary_path_refused": true, "canceled_read_not_reported_complete": true, "scope": "Private numeric fixtures through actual native fixed-path handler; not genuine C request events, public Core/browser, installed application or activation."}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(fixture, "native-proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
}
