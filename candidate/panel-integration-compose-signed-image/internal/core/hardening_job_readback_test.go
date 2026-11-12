package core

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestHardeningJobReadUsesScopedSecurityAccess(t *testing.T) {
	s, server, login := wafTaskTestServer(t)
	job, err := s.QueueSoftwareAction("system-hardening", "configure", map[string]any{"profile": "baseline"}, ID(), "waf-admin")
	if err != nil {
		t.Fatal(err)
	}
	wafJob, err := s.QueueSoftwareAction("nginx-waf", "configure", WAFSettings(DefaultWAFConfig()), ID(), "waf-admin")
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/software/system-hardening/jobs/"
	for _, account := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if response := wafTaskTestRead(server, path+job, login(account)); response.Code != http.StatusForbidden {
			t.Fatalf("unexpected access for %s: %d", account, response.Code)
		}
	}
	cookie := login("waf-admin")
	for _, check := range []struct {
		path string
		code int
	}{
		{"/api/jobs/" + job, http.StatusForbidden},
		{path + wafJob, http.StatusNotFound},
		{path + job + "?", http.StatusBadRequest},
	} {
		if response := wafTaskTestRead(server, check.path, cookie); response.Code != check.code {
			t.Fatalf("read %s returned %d, expected %d", check.path, response.Code, check.code)
		}
	}
	response := wafTaskTestRead(server, path+job, cookie)
	var actual map[string]any
	want := map[string]any{"id": job, "kind": "software_configure", "state": "queued", "error": ""}
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		json.Unmarshal(response.Body.Bytes(), &actual) != nil || !reflect.DeepEqual(actual, want) {
		t.Fatal("original scoped task was not returned", response.Code, response.Body.String())
	}
}
