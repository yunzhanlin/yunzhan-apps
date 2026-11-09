package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func platformHealthFixture(at time.Time) map[string]any {
	return map[string]any{"version": "app-modules-1", "time": at.UTC().Format(time.RFC3339), "health": map[string]any{
		"os": "Debian GNU/Linux 13", "arch": "amd64", "cpu_cores": 2, "cpu_available": false, "cpu_percent": nil,
		"memory_available": true, "memory_percent": 25, "memory_total": 4096, "memory_used": 1024,
		"disk_percent_available": true, "disk_percent": 50, "disk_total": 8192, "disk_used": 4096, "disk_available": 3072,
		"nginx_active": false, "sampled_at": at.UTC().Format(time.RFC3339),
	}}
}
func platformHealthRaw(t *testing.T, report map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPlatformHealthStrictProtocolAndUnavailableMetrics(t *testing.T) {
	at := time.Now()
	report := platformHealthFixture(at)
	out, complete, err := decodePlatformHealth(platformHealthRaw(t, report), at, at)
	if err != nil || out == nil || complete || out["health"].(map[string]any)["cpu_percent"] != nil {
		t.Fatal("first CPU sample invented a known zero", err)
	}
	report["health"].(map[string]any)["cpu_available"] = true
	report["health"].(map[string]any)["cpu_percent"] = 0
	if _, complete, err := decodePlatformHealth(platformHealthRaw(t, report), at, at); err != nil || !complete {
		t.Fatal("real available zero refused", err)
	}
	for _, test := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"foreign-version", func(r map[string]any) { r["version"] = "foreign" }},
		{"extra-envelope", func(r map[string]any) { r["token"] = "OWNED-HEALTH-SECRET" }},
		{"missing-health", func(r map[string]any) { delete(r, "health") }},
		{"null-health", func(r map[string]any) { r["health"] = nil }},
		{"old-time", func(r map[string]any) { r["time"] = at.Add(-3 * time.Minute).Format(time.RFC3339) }},
		{"future-time", func(r map[string]any) { r["time"] = at.Add(time.Minute).Format(time.RFC3339) }},
		{"invalid-time", func(r map[string]any) { r["time"] = 17 }},
		{"old-sample", func(r map[string]any) {
			r["health"].(map[string]any)["sampled_at"] = at.Add(-3 * time.Minute).Format(time.RFC3339)
		}},
		{"foreign-arch", func(r map[string]any) { r["health"].(map[string]any)["arch"] = "foreign" }},
		{"missing-availability", func(r map[string]any) { delete(r["health"].(map[string]any), "cpu_available") }},
		{"unknown-as-zero", func(r map[string]any) { r["health"].(map[string]any)["cpu_percent"] = 0 }},
		{"available-null", func(r map[string]any) { r["health"].(map[string]any)["cpu_available"] = true }},
		{"string-availability", func(r map[string]any) { r["health"].(map[string]any)["memory_available"] = "true" }},
		{"unavailable-nonnull", func(r map[string]any) { r["health"].(map[string]any)["memory_available"] = false }},
		{"over-percent", func(r map[string]any) { r["health"].(map[string]any)["memory_percent"] = 101 }},
		{"string-percent", func(r map[string]any) { r["health"].(map[string]any)["memory_percent"] = "25" }},
		{"zero-total", func(r map[string]any) { r["health"].(map[string]any)["memory_total"] = 0 }},
		{"used-over-total", func(r map[string]any) { r["health"].(map[string]any)["disk_used"] = 9000 }},
		{"fractional-bytes", func(r map[string]any) { r["health"].(map[string]any)["disk_used"] = 10.5 }},
		{"unsafe-integer", func(r map[string]any) { r["health"].(map[string]any)["disk_used"] = float64(9007199254740992) }},
		{"missing-cores", func(r map[string]any) { delete(r["health"].(map[string]any), "cpu_cores") }},
		{"text-control", func(r map[string]any) { r["health"].(map[string]any)["os"] = "Debian\nsecret" }},
		{"arbitrary-health", func(r map[string]any) { r["health"].(map[string]any)["password"] = "OWNED-HEALTH-SECRET" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := platformHealthFixture(at)
			test.edit(r)
			if out, complete, err := decodePlatformHealth(platformHealthRaw(t, r), at, at); err == nil || out != nil || complete {
				t.Fatal("malformed protocol accepted")
			}
		})
	}
	good := platformHealthRaw(t, platformHealthFixture(at))
	for name, raw := range map[string][]byte{
		"valid-prefix-trailing": append(append([]byte{}, good...), []byte(` {"foreign":true}`)...),
		"duplicate-top":         bytes.Replace(good, []byte(`"version":"app-modules-1"`), []byte(`"version":"app-modules-1","version":"app-modules-1"`), 1),
		"case-top":              bytes.Replace(good, []byte(`"version":"app-modules-1"`), []byte(`"version":"app-modules-1","VERSION":"app-modules-1"`), 1),
		"escaped-top":           bytes.Replace(good, []byte(`"version":"app-modules-1"`), []byte(`"version":"app-modules-1","\u0076ersion":"app-modules-1"`), 1),
		"duplicate-nested":      bytes.Replace(good, []byte(`"cpu_available":false`), []byte(`"cpu_available":false,"CPU_AVAILABLE":false`), 1),
		"invalid-utf8":          append(good, 0xff), "oversize": append(append([]byte{}, good...), bytes.Repeat([]byte(" "), platformHealthBytes)...), "array": []byte(`[]`), "null": []byte(`null`), "incomplete": good[:len(good)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if out, complete, err := decodePlatformHealth(raw, at, at); err == nil || out != nil || complete {
				t.Fatal("ambiguous bounded protocol accepted")
			}
		})
	}
}

func TestPlatformHealthHTTPSMediaStatusSizeRedirectAndCancellation(t *testing.T) {
	at := time.Now()
	good := platformHealthRaw(t, platformHealthFixture(at))
	var requests, redirectTargets atomic.Int64
	mode := "valid"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/redirect-target" {
			redirectTargets.Add(1)
			t.Error("redirect forwarded bearer")
			return
		}
		if r.URL.Path != "/api/platform/agent" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("1", 64) {
			t.Error("unexpected health request")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch mode {
		case "redirect":
			w.Header().Set("Location", "/redirect-target")
			w.WriteHeader(302)
			return
		case "wrong-status":
			w.WriteHeader(503)
		case "wrong-media":
			w.Header().Set("Content-Type", "text/html")
		case "oversize":
			w.Write(good)
			w.Write(bytes.Repeat([]byte(" "), platformHealthBytes))
			return
		case "foreign":
			io.WriteString(w, `{"password":"OWNED-REMOTE-SECRET"}`)
			return
		case "delay":
			<-r.Context().Done()
			return
		}
		w.Write(good)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer client.CloseIdleConnections()
	for _, scenario := range []string{"valid", "wrong-status", "wrong-media", "oversize", "foreign", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			mode = scenario
			out := readPlatformHealth(context.Background(), client, "owned-host", server.URL, strings.Repeat("1", 64))
			if scenario == "valid" {
				if out["healthy"] != true || out["telemetry_complete"] != false || out["report"] == nil {
					t.Fatal("trusted valid protocol lost")
				}
			} else if out["healthy"] != false || out["report"] != nil || out["error"] == nil {
				t.Fatal("bad response accepted")
			}
			raw, _ := json.Marshal(out)
			if bytes.Contains(raw, []byte("OWNED-REMOTE-SECRET")) || bytes.Contains(raw, []byte(strings.Repeat("1", 64))) {
				t.Fatal("secret reflected")
			}
		})
	}
	if redirectTargets.Load() != 0 {
		t.Fatal("redirect followed")
	}
	mode = "valid"
	untrusted := platformHealthClient()
	defer untrusted.CloseIdleConnections()
	if out := readPlatformHealth(context.Background(), untrusted, "owned-host", server.URL, strings.Repeat("1", 64)); out["healthy"] != false || out["report"] != nil {
		t.Fatal("untrusted TLS accepted")
	}
	before := requests.Load()
	for _, address := range []string{"http://127.0.0.1", "https://user:password@example.invalid", "https://example.invalid/?token=x", "https://example.invalid/#token"} {
		if out := readPlatformHealth(context.Background(), client, "owned-host", address, strings.Repeat("1", 64)); out["healthy"] != false || out["error"] == nil {
			t.Fatal("invalid address accepted")
		}
	}
	if requests.Load() != before {
		t.Fatal("invalid address issued request")
	}
	mode = "delay"
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if out := readPlatformHealth(ctx, client, "owned-host", server.URL, strings.Repeat("1", 64)); out["healthy"] != false || out["report"] != nil || time.Since(start) > time.Second {
		t.Fatal("canceled bounded body accepted or waited")
	}
}
