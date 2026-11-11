//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestSiteDiagnosisPathStaysOnOwnedIngress(t *testing.T) {
	for input, want := range map[string]string{"": "/", "/": "/", "/products/": "/products/", "/中文/文章": "/中文/文章"} {
		if got, err := diagnosisPath(input); err != nil || got != want {
			t.Errorf("valid path %q got %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"https://foreign.example/", "//foreign.example", "/a?token=secret", "/a#fragment",
		"/a%2fb", "/a/../b", "/a/./b", "/a\\b", "/a\nb", "/__panel_health_external", "/" + strings.Repeat("a", 512)} {
		if got, err := diagnosisPath(input); err == nil || got != "" {
			t.Errorf("unsafe path %q was accepted", input)
		}
	}
}

func TestSiteDiagnosisManagedIngressNative(t *testing.T) {
	id := os.Getenv("PANEL_SITE_DIAGNOSIS_NATIVE_ID")
	if id == "" {
		t.Skip("disposable managed PHP site required")
	}
	if os.Geteuid() != 0 || !core.ValidID(id) {
		t.Fatal("root and an exact managed site identity are required")
	}
	service := New(Config{SitesDir: "/srv/panel/sites", NginxBin: "/usr/sbin/nginx"})
	for _, probe := range []struct {
		path, verdict string
		code          int
	}{{"/process.php", "pass", 200}, {"/site-diagnosis-not-found-c97", "fail", 404}} {
		value, err := service.moduleDiagnosis(context.Background(), core.AppModuleInput{SiteID: id, Path: probe.path, DiagnosisSymptom: "not-found"})
		if err != nil {
			t.Fatal(err)
		}
		report := value.(map[string]any)
		if report["site_id"] != id || report["domain"] != "c95-control.example.test" || report["path"] != probe.path {
			t.Fatal("diagnosis did not resolve the owned fixture")
		}
		checks := report["checks"].(map[string]map[string]any)
		if checks["binding"]["verdict"] != "pass" || checks["nginx"]["verdict"] != "pass" ||
			checks["http"]["status"] != probe.code || checks["http"]["verdict"] != probe.verdict {
			t.Fatalf("real ingress results differ: %v", checks)
		}
	}
	value, err := service.moduleDiagnosisBatch(context.Background(), core.AppModuleInput{
		SiteIDs: []string{id, strings.Repeat("0", 32)}, Path: "/process.php",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Diagnoses []struct {
			SiteID string         `json:"site_id"`
			Report map[string]any `json:"report"`
			Error  string         `json:"error"`
		} `json:"diagnoses"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil || len(batch.Diagnoses) != 2 ||
		batch.Diagnoses[0].SiteID != id || batch.Diagnoses[0].Report["domain"] != "c95-control.example.test" ||
		batch.Diagnoses[1].Error == "" || batch.Diagnoses[1].Report != nil {
		t.Fatal("batch did not retain the successful report alongside a site failure", err)
	}
	if _, err := service.moduleDiagnosisBatch(context.Background(), core.AppModuleInput{SiteIDs: []string{id, id}}); err == nil {
		t.Fatal("batch accepted a duplicate site")
	}
}

func TestSiteDiagnosisPrioritizesRelatedChecksAndLabelsHTTPFailures(t *testing.T) {
	ordered, err := diagnosisOrder("https")
	if err != nil || len(ordered) != 6 || ordered[0] != "tls_certificate" {
		t.Fatal(ordered, err)
	}
	if _, err := diagnosisOrder("unknown"); err == nil {
		t.Fatal("unknown symptom was accepted")
	}
	for _, check := range []struct {
		status  int
		elapsed int64
		verdict string
	}{
		{http.StatusOK, 20, "pass"},
		{http.StatusOK, 1500, "warn"},
		{http.StatusMovedPermanently, 20, "warn"},
		{http.StatusForbidden, 20, "fail"},
		{http.StatusNotFound, 20, "fail"},
		{http.StatusBadGateway, 20, "fail"},
		{http.StatusServiceUnavailable, 20, "fail"},
		{http.StatusGatewayTimeout, 20, "fail"},
	} {
		got := diagnosisHTTPResult(check.status, check.elapsed, nil)
		if got["verdict"] != check.verdict || got["status"] != check.status || got["response_ms"] != check.elapsed ||
			got["ok"] != (check.verdict == "pass") || got["detail"] == "" {
			t.Errorf("unexpected result for HTTP %d: %v", check.status, got)
		}
	}
}
