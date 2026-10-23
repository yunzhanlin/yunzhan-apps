package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlatformMaintenanceHTTPSeparateTokenCSRFACLAndLostRootReply(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "maintenance-http-admin", "admin", nil)
	accessUser(t, s, "maintenance-http-viewer", "viewer", nil)
	accessUser(t, s, "maintenance-http-restricted", "admin", []string{"overview"})
	a, e := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if e != nil {
		t.Fatal(e)
	}
	rootCalls := 0
	lost := true
	var original PlatformMaintenanceRecord
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var reply any
		switch r.URL.Path {
		case "/v1/app-modules/platform-ops":
			reply = map[string]any{"status": SoftwareAppStatus{ID: "platform-ops", Installed: true, Healthy: true, Version: PlatformMaintenanceAppVersion, InstallationID: maintenanceTestInstallationID}}
		case "/v1/platform-maintenance/plan":
			reply = PlatformMaintenancePlan{Format: 1, SHA: strings.Repeat("e", 64), Commands: PlatformMaintenanceCommands()}
		case "/v1/platform-maintenance/commands":
			rootCalls++
			raw, _ := io.ReadAll(r.Body)
			in, e := DecodePlatformMaintenanceNativeRequest(raw)
			if e != nil {
				t.Fatal(e)
			}
			original = PlatformMaintenanceRecord{Format: 1, Request: in, RequestSHA: PlatformMaintenanceRequestSHA(in), State: "completed", Outcome: "reload_signal_submitted"}
			if lost {
				return nil, errors.New("synthetic lost Root response")
			}
			reply = original
		default:
			if r.URL.Path == "/v1/platform-maintenance/commands/"+original.Request.Input.RequestID && r.Method == "GET" {
				reply = original
			} else {
				t.Fatal("unexpected Root operation", r.Method, r.URL.Path)
			}
		}
		raw, _ := json.Marshal(reply)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	call := func(method, path string, body []byte, cookie *http.Cookie, csrf, bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := call("POST", "/api/login", []byte(`{"username":"`+name+`","password":"access-test-password-long"}`), nil, "", "")
		var auth accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &auth) != nil {
			t.Fatal("login", w.Code)
		}
		return w.Result().Cookies()[0], auth.CSRF
	}
	grantBody, _ := json.Marshal(PlatformMaintenanceGrantInput{Commands: PlatformMaintenanceCommands(), Minutes: 60, Confirm: "GRANT NGINX MAINTENANCE"})
	base := "/api/app-modules/platform-ops/maintenance"
	for _, name := range []string{"maintenance-http-viewer", "maintenance-http-restricted"} {
		cookie, csrf := login(name)
		if w := call("POST", base+"/grants", grantBody, cookie, csrf, ""); w.Code != 403 {
			t.Fatal("grant ACL", w.Code)
		}
	}
	cookie, csrf := login(admin.Username)
	if w := call("POST", base+"/grants", grantBody, cookie, "wrong", ""); w.Code != 403 {
		t.Fatal("grant CSRF", w.Code)
	}
	w := call("POST", base+"/grants", grantBody, cookie, csrf, "")
	var grant struct{ Token, GrantID string }
	var rawGrant map[string]any
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &rawGrant) != nil {
		t.Fatal("issue", w.Code, w.Body.String())
	}
	grant.Token = rawGrant["token"].(string)
	grant.GrantID = rawGrant["grant_id"].(string)
	if _, e = s.DB.Exec("INSERT INTO app_platform_tokens VALUES(?,?)", Hash(strings.Repeat("1", 64)), Now()); e != nil {
		t.Fatal(e)
	}
	for _, old := range []string{strings.Repeat("1", 64), grant.GrantID} {
		if w := call("GET", "/api/platform-maintenance/plan", nil, nil, "", old); w.Code != 401 {
			t.Fatal("readonly or digest accepted", w.Code)
		}
	}
	if w := call("GET", "/api/platform-maintenance/plan", nil, nil, "", grant.Token); w.Code != 200 {
		t.Fatal("plan", w.Code, w.Body.String())
	}
	in := maintenanceTestInput(ID(), "nginx-reload")
	body, _ := json.Marshal(in)
	if w := call("POST", "/api/platform-maintenance/commands", body, nil, "", grant.Token); w.Code != 202 {
		t.Fatal("lost response falsely completed", w.Code, w.Body.String())
	}
	if rootCalls != 1 {
		t.Fatal("Root dispatched count", rootCalls)
	}
	if w := call("POST", "/api/platform-maintenance/commands", body, nil, "", grant.Token); w.Code != 202 || rootCalls != 1 {
		t.Fatal("original pending retried", w.Code, rootCalls)
	}
	other := in
	other.RequestID = ID()
	otherBody, _ := json.Marshal(other)
	if w := call("POST", "/api/platform-maintenance/commands", otherBody, nil, "", grant.Token); w.Code != 409 || rootCalls != 1 {
		t.Fatal("new ID bypassed unknown reload", w.Code, rootCalls)
	}
	lost = false
	if w := call("GET", "/api/platform-maintenance/commands/"+in.RequestID, nil, nil, "", grant.Token); w.Code != 200 || rootCalls != 1 {
		t.Fatal("read reconciliation reran Root", w.Code, rootCalls)
	}
	if w := call("POST", "/api/platform-maintenance/commands", body, nil, "", grant.Token); w.Code != 200 || rootCalls != 1 {
		t.Fatal("completed replay reran Root", w.Code, rootCalls)
	}
	if w := call("POST", base+"/grants/"+grant.GrantID+"/revoke", []byte("{}"), cookie, csrf, ""); w.Code != 200 {
		t.Fatal("revoke", w.Code, w.Body.String())
	}
	if w := call("GET", "/api/platform-maintenance/plan", nil, nil, "", grant.Token); w.Code != 401 {
		t.Fatal("revoked authenticated", w.Code)
	}
	if w := call("POST", base+"/operations/"+in.RequestID+"/reconcile", []byte("{}"), cookie, csrf, ""); w.Code != 200 || rootCalls != 1 {
		t.Fatal("local admin could not inspect original after revocation", w.Code, rootCalls)
	}
	if w := call("GET", base+"/operations", nil, cookie, csrf, ""); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(in.RequestID)) || bytes.Contains(w.Body.Bytes(), []byte(grant.Token)) {
		t.Fatal("public inventory leaked secret or incomplete", w.Code)
	}
}
