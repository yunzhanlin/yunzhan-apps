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

func TestNetworkIDSRuleFeedReadOnlySignedInventoryAndAccess(t *testing.T) {
	repository, selection, requests := networkRuleFeedRepositoryFixture(t)
	s := testStore(t)
	admin := accessUser(t, s, "admin", "admin", nil)
	accessUser(t, s, "limited", "admin", []string{"runtimes"})
	accessUser(t, s, "viewer", "viewer", nil)
	jobID, err := s.QueueNetworkIDSRuleFeed(selection, "own-read-job", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	a.AppCatalog = repository
	calls := 0
	installed, known := true, true
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" {
			t.Fatal("viewing rules dispatched mutation", r.URL)
		}
		var out any
		switch r.URL.Path {
		case "/v1/app-modules/network-threat-detection":
			out = map[string]any{"status": SoftwareAppStatus{Installed: installed}}
		case "/v1/network-ids/rule-feeds":
			out = NetworkIDSRuleFeedInventory{StateKnown: known, Rows: []NetworkIDSRuleFeedStored{}, Error: func() string {
				if known {
					return ""
				}
				return "own unverified data fixture"
			}()}
		default:
			t.Fatal("unexpected viewing dispatch", r.URL)
		}
		raw, _ := json.Marshal(out)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	endpoint := "/api/software/network-threat-detection/rule-feeds?refresh=1"
	if w := request("GET", endpoint, "", nil); w.Code != 401 {
		t.Fatal("anonymous inventory", w.Code)
	}
	for _, name := range []string{"viewer", "limited", "admin"} {
		login := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, nil)
		if login.Code != 200 {
			t.Fatal("fixture login", login.Code)
		}
		cookie := login.Result().Cookies()[0]
		if name != "admin" {
			if w := request("GET", endpoint, "", cookie); w.Code != 403 || calls != 0 || requests.Load() != 0 {
				t.Fatal("unauthorized inventory dispatched", w.Code, calls, requests.Load())
			}
			continue
		}
		for _, stateKnown := range []bool{true, false} {
			known = stateKnown
			w := request("GET", endpoint, "", cookie)
			var page NetworkIDSRuleFeedPage
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || !page.DataOnly || page.CaptureStarted || page.NativeSyntaxVerified || len(page.Available) != 1 || page.Available[0].Selection != selection || !page.Available[0].Supported || page.Available[0].Bytes < 1 || len(page.Available[0].Assets) != 6 || page.Stored.StateKnown != known || len(page.Jobs) != 1 || page.Jobs[0].ID != jobID {
				t.Fatal("false readiness or wrong signed metadata", w.Code, w.Body.String())
			}
		}
		if calls != 4 || requests.Load() != 4 {
			t.Fatal("inventory fetched data or privileged mutation", calls, requests.Load())
		}
		installed = false
		if w := request("GET", endpoint, "", cookie); w.Code != 409 || requests.Load() != 4 || calls != 5 {
			t.Fatal("viewing auto-installed absent module", w.Code, calls, requests.Load())
		}
	}
}
