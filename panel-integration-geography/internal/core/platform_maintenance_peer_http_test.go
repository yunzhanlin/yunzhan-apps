package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Two actual HTTPS Core servers and SQLite stores. The Root executor and its
// command receipt remain explicit fixtures; this is not installed-host proof.
func TestPlatformMaintenanceTwoHTTPSPeersKeepAuthorityAndOriginalID(t *testing.T) {
	newPanel := func(name string) (*Server, identity) {
		s := testStore(t)
		u := accessUser(t, s, name, "admin", nil)
		a, e := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
		if e != nil {
			t.Fatal(e)
		}
		return a, u
	}
	target, owner := newPanel("target-maintenance-admin")
	coordinator, admin := newPanel("coordinator-maintenance-admin")
	limited := accessUser(t, coordinator.Store, "coordinator-limited", "admin", []string{"system-tools"})
	var mu sync.Mutex
	posts, reads := 0, 0
	receipts := map[string]PlatformMaintenanceRecord{}
	rootFixture := func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		var reply any
		switch r.URL.Path {
		case "/v1/app-modules/platform-ops":
			reply = map[string]any{"status": SoftwareAppStatus{ID: "platform-ops", Installed: true, Healthy: true, Version: PlatformMaintenanceAppVersion, InstallationID: maintenanceTestInstallationID}}
		case "/v1/platform-maintenance/plan":
			reply = PlatformMaintenancePlan{Format: 1, SHA: strings.Repeat("e", 64), Commands: PlatformMaintenanceCommands()}
		case "/v1/platform-maintenance/commands":
			posts++
			raw, _ := io.ReadAll(r.Body)
			req, e := DecodePlatformMaintenanceNativeRequest(raw)
			if e != nil {
				return nil, e
			}
			receipts[req.Input.RequestID] = PlatformMaintenanceRecord{Format: 1, Request: req, RequestSHA: PlatformMaintenanceRequestSHA(req), State: "completed", Outcome: "reload_signal_submitted"}
			return nil, errors.New("explicit fixture: Root response lost after submission")
		default:
			id := strings.TrimPrefix(r.URL.Path, "/v1/platform-maintenance/commands/")
			v, ok := receipts[id]
			if !ok || r.Method != "GET" {
				return nil, errors.New("unexpected executor request")
			}
			reads++
			reply = v
		}
		raw, _ := json.Marshal(reply)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	}
	target.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(rootFixture)}}
	coordinator.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(rootFixture)}}
	targetTLS := httptest.NewTLSServer(target)
	defer targetTLS.Close()
	coordinatorTLS := httptest.NewTLSServer(coordinator)
	defer coordinatorTLS.Close()
	// Trust only the explicit test certificates; never skip hostname verification.
	pool := x509.NewCertPool()
	pool.AddCert(targetTLS.Certificate())
	pool.AddCert(coordinatorTLS.Certificate())
	originalTransport := http.DefaultTransport
	trustedTransport := originalTransport.(*http.Transport).Clone()
	trustedTransport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = trustedTransport
	defer func() { trustedTransport.CloseIdleConnections(); http.DefaultTransport = originalTransport }()
	client := coordinatorTLS.Client()
	call := func(path string, body any, cookie *http.Cookie, csrf string) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, e := http.NewRequest("POST", coordinatorTLS.URL+path, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", coordinator.Config.Origin)
		req.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		response, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		wire, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, wire
	}
	login := func(u identity) (*http.Cookie, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"username": u.Username, "password": "access-test-password-long"})
		r, e := http.NewRequest("POST", coordinatorTLS.URL+"/api/login", bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", coordinator.Config.Origin)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		var session accountSession
		if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&session) != nil || len(response.Cookies()) == 0 {
			t.Fatal("real HTTPS session login failed", response.StatusCode)
		}
		return response.Cookies()[0], session.CSRF
	}
	cookie, csrf := login(admin)
	limitedCookie, limitedCSRF := login(limited)
	issued, e := target.Store.issuePlatformMaintenanceGrant(context.Background(), owner.ID, PlatformMaintenanceGrantInput{Commands: PlatformMaintenanceCommands(), Minutes: 60, Confirm: "GRANT NGINX MAINTENANCE"}, maintenanceTestInstallationID)
	if e != nil {
		t.Fatal(e)
	}
	grant := issued.(map[string]any)
	token := grant["token"].(string)
	base := "/api/app-modules/platform-ops/maintenance/remote"
	if code, wire := call(base+"/plan", platformMaintenancePeer{URL: targetTLS.URL, Token: token}, cookie, csrf); code != 200 {
		t.Fatal("HTTPS original plan failed", code, string(wire))
	} else if _, e := decodePlatformMaintenanceRemotePlan(wire, token); e != nil {
		t.Fatal(e)
	}
	original := platformMaintenanceRemoteInput{URL: targetTLS.URL, Token: token, ActorID: owner.ID, Operation: maintenanceTestInput(ID(), "nginx-reload")}
	if code, _ := call(base+"/commands", original, limitedCookie, limitedCSRF); code != 403 {
		t.Fatal("limited coordinator could reload", code)
	}
	for _, mismatch := range []string{"actor", "plan", "readonly-secret"} {
		bad := original
		switch mismatch {
		case "actor":
			bad.ActorID = ID()
		case "plan":
			bad.Operation.ExpectedPlanSHA = strings.Repeat("f", 64)
			bad.Operation.Confirm = "RELOAD NGINX " + bad.Operation.ExpectedPlanSHA
		case "readonly-secret":
			bad.Token = strings.Repeat("1", 64)
		}
		if code, _ := call(base+"/commands", bad, cookie, csrf); code == 200 || code == 202 {
			t.Fatal("unverified authority dispatched", mismatch, code)
		}
	}
	mu.Lock()
	count := posts
	mu.Unlock()
	if count != 0 {
		t.Fatal("authority check reached Root mutation", count)
	}
	if code, wire := call(base+"/commands", original, cookie, csrf); code != 202 || !platformMaintenancePending(wire, original.Operation.RequestID) {
		t.Fatal("lost response did not retain original", code, string(wire))
	}
	if code, _ := call(base+"/commands", original, cookie, csrf); code != 202 {
		t.Fatal("same pending ID changed state", code)
	}
	changed := original
	changed.Operation.RequestID = ID()
	if code, _ := call(base+"/commands", changed, cookie, csrf); code == 200 || code == 202 {
		t.Fatal("different ID bypassed unresolved reload", code)
	}
	if code, wire := call(base+"/commands/status", original, cookie, csrf); code != 200 {
		t.Fatal("original read-only reconciliation failed", code, string(wire))
	} else {
		request := PlatformMaintenanceNativeRequest{Format: 1, GrantID: Hash(token), ActorID: owner.ID, Input: original.Operation}
		if out, e := DecodePlatformMaintenanceRecord(wire, request); e != nil || out.State != "completed" {
			t.Fatal("original receipt mismatch", e)
		}
	}
	mu.Lock()
	count, inspections := posts, reads
	mu.Unlock()
	if count != 1 || inspections != 1 {
		t.Fatal("HTTPS bridge repeated mutation", count, inspections)
	}
	if _, e := target.Store.DB.Exec("UPDATE platform_maintenance_grants SET revoked=1 WHERE token_hash=?", Hash(token)); e != nil {
		t.Fatal(e)
	}
	if code, _ := call(base+"/plan", platformMaintenancePeer{URL: targetTLS.URL, Token: token}, cookie, csrf); code == 200 {
		t.Fatal("revoked remote authority accepted")
	}
	for _, s := range []*Store{coordinator.Store, target.Store} {
		rows, e := s.DB.Query("SELECT actor,action,target,result FROM audit_logs")
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			var actor, action, destination, result string
			if e := rows.Scan(&actor, &action, &destination, &result); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(actor+action+destination+result, token) {
				t.Fatal("audit persisted maintenance secret")
			}
		}
		if e := rows.Err(); e != nil {
			t.Fatal(e)
		}
		rows.Close()
	}
}
