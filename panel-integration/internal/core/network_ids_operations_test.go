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

func TestNetworkIDSOperationInputIsClosedAndActionSpecific(t *testing.T) {
	for _, test := range []struct{ action, raw string }{
		{"ids-start", `{"expected_revision":1}`},
		{"ids-config", `{"expected_revision":0,"network_interface":"lo","home_networks":["127.0.0.1/32"]}`},
		{"ids-boot", `{"expected_revision":2,"enabled":false}`},
	} {
		in, err := decodeNetworkIDSOperationInput(test.action, []byte(test.raw))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(in)
		if _, err := DecodeNetworkIDSOperationRequest(raw); err != nil {
			t.Fatal("typed roundtrip", err)
		}
	}
	for _, raw := range []string{
		`{}`, `{"EXPECTED_REVISION":1}`, `{"expected_revision":1,"expected_revision":1}`, `{"expected_revision":1,"expected_\u0072evision":1}`,
		`{"expected_revision":null}`, `{"expected_revision":-1}`, `{"expected_revision":1.1}`, `{"expected_revision":1,"enabled":false}`,
		`{"expected_revision":1,"home_networks":[]}`, `{"expected_revision":1,"network_interface":"lo"}`, `{"expected_revision":1,"path":"/etc/passwd"}`,
		`{"expected_revision":1} {}`, `{"expected_revision":1,"input":{}}`, strings.Repeat(" ", 4096) + `{"expected_revision":1}`,
	} {
		if _, err := decodeNetworkIDSOperationInput("ids-start", []byte(raw)); err == nil {
			t.Fatal("unsafe control accepted", raw[:min(len(raw), 120)])
		}
	}
	for _, raw := range []string{
		`{"action":"ids-start","input":{"expected_revision":1},"source":"/tmp"}`,
		`{"action":"ids-start","action":"ids-stop","input":{"expected_revision":1}}`,
		`{"Action":"ids-start","input":{"expected_revision":1}}`,
		`{"action":"shell","input":{"expected_revision":1}}`, `{"action":"ids-start","input":null}`,
	} {
		if _, err := DecodeNetworkIDSOperationRequest([]byte(raw)); err == nil {
			t.Fatal("unsafe request accepted", raw)
		}
	}
}

func TestNetworkIDSOperationCoreReturnsAcceptanceNotSynchronousMutation(t *testing.T) {
	store := testStore(t)
	accessUser(t, store, "admin", "admin", nil)
	a, err := NewServer(store, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	var receipts []NetworkIDSOperation
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(r.URL.Path, "/v1/network-ids/operations/") {
			t.Fatal("old synchronous operation dispatched", r.URL)
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/network-ids/operations/")
		var out NetworkIDSOperation
		if r.Method == "POST" {
			raw, _ := io.ReadAll(r.Body)
			in, err := DecodeNetworkIDSOperationRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			out = NetworkIDSOperation{ID: id, Action: in.Action, Input: in.Input, State: "queued", CreatedAt: Now(), UpdatedAt: Now(), Steps: []Step{}}
			receipts = append(receipts, out)
		} else {
			out = receipts[0]
			out.State = "running"
		}
		raw, _ := json.Marshal(out)
		return &http.Response{StatusCode: 202, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"access-test-password-long"}`))
	login.Header.Set("Origin", a.Config.Origin)
	login.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, login)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var session accountSession
	json.Unmarshal(w.Body.Bytes(), &session)
	request := func(method, path, raw, key, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(raw))
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		out := httptest.NewRecorder()
		a.ServeHTTP(out, r)
		return out
	}
	endpoint := "/api/app-modules/network-threat-detection/ids-start"
	if out := request("POST", endpoint, `{"expected_revision":1}`, "same-retry", ""); out.Code != 403 || len(receipts) != 0 {
		t.Fatal("missing CSRF dispatched", out.Code)
	}
	if out := request("POST", endpoint, `{"expected_revision":1}`, "", session.CSRF); out.Code != 400 || len(receipts) != 0 {
		t.Fatal("missing key dispatched", out.Code)
	}
	if out := request("POST", endpoint, `{"expected_revision":1,"shell":"id"}`, "same-retry", session.CSRF); out.Code != 400 || len(receipts) != 0 {
		t.Fatal("unknown input dispatched", out.Code)
	}
	for i := 0; i < 2; i++ {
		if out := request("POST", endpoint, `{"expected_revision":1}`, "same-retry", session.CSRF); out.Code != 202 {
			t.Fatal("no accepted receipt", out.Code, out.Body.String())
		}
	}
	if len(receipts) != 2 || receipts[0].ID != receipts[1].ID || receipts[0].State != "queued" {
		t.Fatal("retry identity changed or acceptance called success")
	}
	if out := request("GET", "/api/app-modules/network-threat-detection/operations/"+receipts[0].ID, "", "", session.CSRF); out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	var n int
	store.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='network.ids.operation.observe' AND result='queued'`).Scan(&n)
	if n != 2 {
		t.Fatal("acceptance not honestly audited", n)
	}
}
