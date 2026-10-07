//go:build linux

package executor

import (
	"encoding/json"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWAFBodyEventParserNeverExportsRequestContext(t *testing.T) {
	valid := "2026/10/08 01:00:00 [warn] 123#123: yunzhan_waf_body rule=941100 phase=2 severity=2 disruptive=1 site=" + strings.Repeat("a", 32)
	event, ok := parseWAFBodyEvent([]byte(valid))
	if !ok || event.RuleID != 941100 || event.Phase != 2 || !event.Disruptive {
		t.Fatal(event, ok)
	}
	for _, line := range []string{valid + ", request: POST /private?token=secret", valid + " Cookie=private", strings.Replace(valid, "phase=2", "phase=9", 1), strings.Replace(valid, "severity=2", "severity=20", 1), strings.Replace(valid, "rule=941100", "rule=999999999999999999", 1), strings.Replace(valid, "2026/10/08", "2026/13/40", 1), strings.Replace(valid, "site="+strings.Repeat("a", 32), "site=owned-secret.invalid", 1)} {
		if _, ok := parseWAFBodyEvent([]byte(line)); ok {
			t.Fatal("untrusted context accepted")
		}
	}
	s := wafPolicyFixture(t)
	path := s.systemPath("/var/log/nginx/panel-waf-body-events.log")
	os.MkdirAll(filepath.Dir(path), 0755)
	if err := os.WriteFile(path, []byte(valid+"\n"+valid+" private_content\n"), 0640); err != nil {
		t.Fatal(err)
	}
	page, err := s.readWAFBodyEvents()
	if err != nil || !page.Available || len(page.Events) != 1 || page.Rejected != 1 {
		t.Fatal(page, err)
	}
	data, _ := json.Marshal(page)
	if strings.Contains(string(data), "private_content") {
		t.Fatal("raw rejected log exposed")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readWAFBodyEvents(); err == nil {
		t.Fatal("writable log trusted")
	}
}

func TestWAFBodyReportActualLogNativeQA(t *testing.T) {
	if os.Getenv("PANEL_WAF_BODY_REPORT_QA") != "1" {
		t.Skip("explicit disposable QA gate required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse main or unknown host")
	}
	s := nativeWAFService()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-report?limit=10", nil))
	var out core.WAFBodyReport
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Available || out.Matches < 1 || len(out.Events) < 1 || out.Counting != "rule_matches_not_http_requests_or_blocks" {
		t.Fatal("actual numeric-only rule report", w.Code, w.Body.String())
	}
	for _, field := range []string{`"blocked"`, `"request"`, `"ip"`, `"cookie"`, `private_site_waf_`} {
		if strings.Contains(w.Body.String(), field) {
			t.Fatal("unexpected private/request claim", field)
		}
	}
}
