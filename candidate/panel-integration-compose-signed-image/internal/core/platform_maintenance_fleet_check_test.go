package core

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlatformMaintenanceFleetHTTPPreservesEachOriginalRequest(t *testing.T) {
	s := testStore(t)
	accessUser(t, s, "fleet-admin", "admin", []string{"system-tools"})
	accessUser(t, s, "fleet-restricted", "admin", []string{"overview"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	version := PlatformMaintenanceFleetAppVersion
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		reply, _ := json.Marshal(map[string]any{"status": SoftwareAppStatus{ID: "platform-ops", Installed: true, Healthy: true, Version: version, InstallationID: maintenanceTestInstallationID}})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(reply))}, nil
	})}}
	do := func(path, verb string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(verb, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", a.Config.Origin)
		req.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res := httptest.NewRecorder()
		a.ServeHTTP(res, req)
		return res
	}
	login := func(user string) (*http.Cookie, string) {
		t.Helper()
		res := do("/api/login", "POST", map[string]string{"username": user, "password": "access-test-password-long"}, nil, "")
		var session accountSession
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &session) != nil || len(res.Result().Cookies()) == 0 || session.CSRF == "" {
			t.Fatal("login failed", res.Code)
		}
		return res.Result().Cookies()[0], session.CSRF
	}
	if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)
VALUES('platform-ops','platform-ops',?,?, 'platform-ops',?)`, PlatformMaintenanceFleetAppVersion, Hash("signed fixture"), Now()); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := login("fleet-admin")
	restricted, restrictedCSRF := login("fleet-restricted")
	var sent, planReads, inspections atomic.Int32
	pool := x509.NewCertPool()
	newPeer := func(status string) platformMaintenanceRemoteInput {
		in := platformMaintenanceRemoteInput{Token: Hash(ID()), ActorID: ID(), Operation: maintenanceTestInput(ID(), "nginx-check")}
		req := PlatformMaintenanceNativeRequest{Format: 1, ActorID: in.ActorID, GrantID: Hash(in.Token), Input: in.Operation}
		terminal := PlatformMaintenanceRecord{Format: 1, Request: req, RequestSHA: PlatformMaintenanceRequestSHA(req), State: "completed", Outcome: "config_valid"}
		if status == "failed" {
			terminal.State, terminal.Outcome = "failed", "command_failed"
		}
		peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+in.Token {
				w.WriteHeader(403)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == "GET" && r.URL.Path == "/api/platform-maintenance/plan":
				planReads.Add(1)
				digest := in.Operation.ExpectedPlanSHA
				if status == "stale" {
					digest = strings.Repeat("f", 64)
				}
				_ = json.NewEncoder(w).Encode(PlatformMaintenanceRemotePlan{
					Plan:    PlatformMaintenancePlan{Format: 1, SHA: digest, Commands: PlatformMaintenanceCommands()},
					GrantID: req.GrantID, ActorID: req.ActorID, AllowedCommands: []string{"nginx-check"}, Expires: time.Now().Add(time.Minute).Unix(),
				})
			case r.Method == "POST" && r.URL.Path == "/api/platform-maintenance/commands":
				sent.Add(1)
				raw, _ := io.ReadAll(r.Body)
				got, err := DecodePlatformMaintenanceInput(raw)
				if err != nil || got != in.Operation || status == "stale" {
					t.Error("unexpected command received")
					w.WriteHeader(400)
					return
				}
				if status == "lost" {
					w.WriteHeader(503)
					return
				}
				_ = json.NewEncoder(w).Encode(terminal)
			case r.Method == "GET" && r.URL.Path == "/api/platform-maintenance/commands/"+in.Operation.RequestID:
				inspections.Add(1)
				_ = json.NewEncoder(w).Encode(terminal)
			default:
				t.Error("unexpected peer route", r.Method, r.URL.Path)
				w.WriteHeader(404)
			}
		}))
		t.Cleanup(peer.Close)
		pool.AddCert(peer.Certificate())
		in.URL = peer.URL
		return in
	}
	targets := []platformMaintenanceRemoteInput{newPeer("passed"), newPeer("failed"), newPeer("lost"), newPeer("stale")}
	orig := http.DefaultTransport
	transport := orig.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = transport
	t.Cleanup(func() { transport.CloseIdleConnections(); http.DefaultTransport = orig })
	base := "/api/app-modules/platform-ops/maintenance/remote"
	fleet := base + "/fleet/checks"
	wrap := func(v []platformMaintenanceRemoteInput) map[string]any { return map[string]any{"targets": v} }
	version = PlatformMaintenanceAppVersion
	if res := do(fleet, "POST", wrap(targets), cookie, csrf); res.Code != 409 {
		t.Fatal("previous exact release enabled fleet", res.Code)
	}
	version = PlatformMaintenanceFleetAppVersion
	if _, err := s.DB.Exec("UPDATE app_registry_receipts SET version='1.3.0' WHERE app_id='platform-ops'"); err != nil {
		t.Fatal(err)
	}
	if res := do(fleet, "POST", wrap(targets), cookie, csrf); res.Code != 409 {
		t.Fatal("fleet enabled without matching signed receipt", res.Code)
	}
	if _, err := s.DB.Exec("UPDATE app_registry_receipts SET version='1.3.1' WHERE app_id='platform-ops'"); err != nil {
		t.Fatal(err)
	}

	if res := do(fleet, "POST", wrap(targets), restricted, restrictedCSRF); res.Code != 403 {
		t.Fatal("restricted admin was allowed", res.Code)
	}
	if res := do(fleet, "POST", wrap(targets), cookie, "wrong"); res.Code != 403 {
		t.Fatal("wrong CSRF was allowed", res.Code)
	}
	for _, mutate := range []func([]platformMaintenanceRemoteInput){
		func(v []platformMaintenanceRemoteInput) { v[1].URL = v[0].URL + "/other" },
		func(v []platformMaintenanceRemoteInput) {
			v[0].URL = "https://[::ffff:127.0.0.1]:0443"
			v[1].URL = "https://127.0.0.1"
		},
		func(v []platformMaintenanceRemoteInput) { v[1].Token = v[0].Token },
		func(v []platformMaintenanceRemoteInput) { v[1].Operation.RequestID = v[0].Operation.RequestID },
		func(v []platformMaintenanceRemoteInput) { v[1].Operation = maintenanceTestInput(ID(), "nginx-reload") },
	} {
		v := append([]platformMaintenanceRemoteInput(nil), targets...)
		mutate(v)
		if res := do(fleet, "POST", wrap(v), cookie, csrf); res.Code != 400 {
			t.Fatal("invalid fleet dispatched", res.Code)
		}
	}
	if planReads.Load() != 0 || sent.Load() != 0 {
		t.Fatal("invalid requests reached peers")
	}
	run := func() []platformMaintenanceFleetResult {
		t.Helper()
		res := do(fleet, "POST", wrap(targets), cookie, csrf)
		var data struct {
			All     *bool                            `json:"all_succeeded"`
			Results []platformMaintenanceFleetResult `json:"results"`
		}
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &data) != nil ||
			len(data.Results) != len(targets) || data.All == nil || *data.All {
			t.Fatal("partial fleet was reported incorrectly", res.Code, res.Body.String())
		}
		return data.Results
	}
	first := run()
	for i, state := range []string{"completed", "failed", "needs_attention", "not_dispatched"} {
		if first[i].State != state || first[i].RequestID != targets[i].Operation.RequestID {
			t.Fatal("incorrect original result", i, first[i])
		}
	}
	// A changed (or no longer reachable) endpoint cannot erase the fact that
	// this coordinator already attempted that request ID.
	originalURL := targets[2].URL
	targets[2].URL = "https://unreachable.invalid"
	second := run()
	targets[2].URL = originalURL
	if sent.Load() != 3 || second[0].State != "needs_attention" || second[1].State != "needs_attention" || second[2].State != "needs_attention" || second[3].State != "not_dispatched" {
		t.Fatal("batch automatically replayed original commands", sent.Load(), second)
	}
	if res := do(base+"/commands", "POST", targets[2], cookie, csrf); res.Code != 409 || sent.Load() != 3 {
		t.Fatal("single-host endpoint replayed a fleet command", res.Code, sent.Load())
	}
	res := do(base+"/commands/status", "POST", targets[2], cookie, csrf)
	if res.Code != 200 || inspections.Load() != 1 || sent.Load() != 3 {
		t.Fatal("read-only reconciliation did not observe original result", res.Code, inspections.Load(), sent.Load())
	}
	rows, err := s.DB.Query("SELECT result FROM audit_logs WHERE action LIKE 'platform.maintenance.remote.%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			t.Fatal(err)
		}
		for _, row := range targets {
			if strings.Contains(result, row.Token) {
				t.Fatal("coordinator persisted a secret")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
