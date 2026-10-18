package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInstalledModuleIdentityRequiresDeclaredExactKnownRecord(t *testing.T) {
	for _, definition := range AppModules() {
		id := definition.ID
		good := SoftwareAppStatus{ID: id, Installed: true}
		if !knownInstalledAppModule(id, good) {
			t.Fatal("disabled/unhealthy application must remain inspectable and repairable", id)
		}
		for _, bad := range []SoftwareAppStatus{{Installed: true}, {ID: "other", Installed: true}, {ID: id, Installed: true, StateUnknown: true}, {ID: id}} {
			if knownInstalledAppModule(id, bad) {
				t.Fatal("invalid installation identity accepted", id, bad)
			}
		}
	}
	if knownInstalledAppModule("not-declared", SoftwareAppStatus{ID: "not-declared", Installed: true}) {
		t.Fatal("unknown module adopted")
	}
}

func TestAllGenericModuleHTTPActionsRefuseUnknownIdentityBeforeBusiness(t *testing.T) {
	store := testStore(t)
	accessUser(t, store, "identity-admin", "admin", nil)
	accessUser(t, store, "identity-target", "viewer", nil)
	a, err := NewServer(store, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"identity-admin","password":"access-test-password-long"}`))
	login.Header.Set("Origin", a.Config.Origin)
	login.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, login)
	var session accountSession
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &session) != nil || session.CSRF == "" {
		t.Fatal("actual fixture login failed", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	request := func(id, action, raw, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/app-modules/"+id+"/"+action, strings.NewReader(raw))
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		out := httptest.NewRecorder()
		a.ServeHTTP(out, r)
		return out
	}
	counts := func() []int {
		t.Helper()
		var out []int
		for _, table := range []string{"users", "app_user_roles", "app_user_menus", "app_daily_reports", "app_module_events", "notifications", "jobs", "audit_logs"} {
			var n int
			if err := store.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		return out
	}
	for _, d := range AppModules() {
		for _, scenario := range []string{"missing-id", "wrong-id", "unknown", "uninstalled", "wrong-type", "transport-error"} {
			t.Run(d.ID+"/"+scenario, func(t *testing.T) {
				reads := 0
				a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method != "GET" || r.URL.Path != "/v1/app-modules/"+d.ID {
						t.Fatalf("unknown identity reached business dispatch: %s %s", r.Method, r.URL.Path)
					}
					reads++
					status := SoftwareAppStatus{ID: d.ID, Installed: true, Enabled: true, Healthy: true}
					switch scenario {
					case "missing-id":
						status.ID = ""
					case "wrong-id":
						status.ID = "other"
					case "unknown":
						status.StateUnknown = true
					case "uninstalled":
						status.Installed = false
					}
					body, _ := json.Marshal(map[string]any{"status": status})
					code := 200
					if scenario == "wrong-type" {
						body = []byte(`{"status":{"installed":"true"}}`)
					} else if scenario == "transport-error" {
						code = 503
					}
					return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
				})}}
				before, _ := json.Marshal(counts())
				if out := request(d.ID, d.Actions[0], `{}`, session.CSRF); out.Code != 409 || reads != 1 {
					t.Fatal("unknown installation not rejected by actual authenticated route", out.Code, reads, out.Body.String())
				}
				for action, raw := range map[string]string{"task-manager/terminate": `{"pid":42,"start_time":1}`, "user-manager/delete": `{"username":"identity-target"}`, "platform-ops/remove": `{"resource_id":"identity-target"}`, "pure-ftpd/service-config": `{"certificate_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`} {
					parts := strings.Split(action, "/")
					if parts[0] == d.ID {
						if out := request(d.ID, parts[1], raw, session.CSRF); out.Code != 409 || reads != 2 {
							t.Fatal("sensitive action bypassed identity gate", action, out.Code, reads)
						}
					}
				}
				if after, _ := json.Marshal(counts()); !bytes.Equal(before, after) {
					t.Fatal("identity refusal changed business/audit records", string(before), string(after))
				}
			})
		}
	}
	reads, writes := 0, 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"status":{"id":"task-manager","installed":true,"enabled":false,"healthy":false}}`
		if r.Method == "POST" && r.URL.Path == "/v1/app-modules/task-manager/run" {
			writes++
			body = `{"processes":[]}`
		} else if r.Method == "GET" && r.URL.Path == "/v1/app-modules/task-manager" {
			reads++
		} else {
			t.Fatal("repair fixture dispatched unrelated endpoint", r.Method, r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	if out := request("task-manager", "run", `{}`, ""); out.Code != 403 || reads != 0 || writes != 0 {
		t.Fatal("CSRF failure reached executor", out.Code, reads, writes)
	}
	if out := request("task-manager", "run", `{}`, session.CSRF); out.Code != 200 || reads != 1 || writes != 1 {
		t.Fatal("known disabled/unhealthy record lost explicit inspection/repair", out.Code, reads, writes)
	}
}

func TestAnalyticsAndRuleFeedHTTPFreezeUnknownInstallIdentityBeforeQueueOrRepository(t *testing.T) {
	a, site, config := analyticsFixture(t, false)
	creation, err := a.Store.NextJob()
	if err != nil || a.Store.Finish(creation, "running", "", nil) != nil {
		t.Fatal("actual private website setup", err)
	}
	a.Config.Listen = "127.0.0.1:19220"
	accessUser(t, a.Store, "identity-routing-admin", "admin", nil)
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"identity-routing-admin","password":"access-test-password-long"}`))
	login.Header.Set("Origin", a.Config.Origin)
	login.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, login)
	var session accountSession
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &session) != nil || session.CSRF == "" {
		t.Fatal("actual private routing login", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	analytics, _ := json.Marshal(AnalyticsConfig{Enabled: true, Clicks: true, Retention: 30, Revision: config.Revision})
	selection, _ := json.Marshal(networkRuleFeedSelectionFixture())
	for _, route := range []struct {
		module, method, path string
		body                 []byte
	}{
		{"website-analytics", "POST", "/api/analytics/sites/" + site.ID + "/config", analytics},
		{"network-threat-detection", "GET", "/api/software/network-threat-detection/rule-feeds?refresh=1", nil},
		{"network-threat-detection", "POST", "/api/software/network-threat-detection/rule-feeds/install", selection},
	} {
		for _, scenario := range []string{"missing-id", "wrong-id", "unknown", "uninstalled"} {
			t.Run(route.method+route.path+"/"+scenario, func(t *testing.T) {
				reads := 0
				a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method != "GET" || r.URL.Path != "/v1/app-modules/"+route.module {
						t.Fatal("unknown identity reached preview, rule inventory or installation", r.Method, r.URL.Path)
					}
					reads++
					status := SoftwareAppStatus{ID: route.module, Installed: true, Version: SoftwareImplementationVersion(route.module)}
					switch scenario {
					case "missing-id":
						status.ID = ""
					case "wrong-id":
						status.ID = "other"
					case "unknown":
						status.StateUnknown = true
					case "uninstalled":
						status.Installed = false
					}
					body, _ := json.Marshal(map[string]any{"status": status})
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
				})}}
				beforeSite, err := a.Store.Site(site.ID)
				if err != nil {
					t.Fatal(err)
				}
				before, _ := json.Marshal(beforeSite)
				counts := func() [2]int {
					t.Helper()
					var v [2]int
					for i, table := range []string{"jobs", "runtime_jobs"} {
						if err := a.Store.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&v[i]); err != nil {
							t.Fatal(err)
						}
					}
					return v
				}
				originalCounts := counts()
				r := httptest.NewRequest(route.method, route.path, bytes.NewReader(route.body))
				r.AddCookie(cookie)
				r.Header.Set("Origin", a.Config.Origin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", session.CSRF)
				r.Header.Set("Idempotency-Key", "identity-refusal-"+route.module+"-"+scenario)
				out := httptest.NewRecorder()
				a.ServeHTTP(out, r)
				if out.Code != 409 || reads != 1 {
					t.Fatal("routing identity refusal not enforced", out.Code, reads, out.Body.String())
				}
				afterSite, err := a.Store.Site(site.ID)
				if err != nil {
					t.Fatal(err)
				}
				after, _ := json.Marshal(afterSite)
				if !bytes.Equal(before, after) || counts() != originalCounts {
					t.Fatal("identity refusal changed original website or queued tasks")
				}
				current, err := a.Store.analyticsConfig(site.ID)
				if err != nil || current != config {
					t.Fatal("identity refusal changed original applied analytics configuration", err)
				}
			})
		}
	}
}
