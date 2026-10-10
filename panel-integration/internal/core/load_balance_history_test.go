package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadBalanceHistoryVersionIsClosedAndRoutingCompatible(t *testing.T) {
	for _, version := range []string{"1.8.0", "1.8.1"} {
		if !LoadBalanceHistoryVersion(version) || !LoadBalanceHealthRoutingVersion(version) {
			t.Fatal("reviewed archive version rejected", version)
		}
	}
	for _, version := range []string{"", "1.7.0", "1.7.1", "1.8.2", "1.9.0", "v1.8.1", "1.8.1 ", "1.8.1-beta"} {
		if LoadBalanceHistoryVersion(version) {
			t.Fatal("unreviewed archive version accepted", version)
		}
	}
}

func TestLoadBalanceHistoryClosedRawBody(t *testing.T) {
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	valid := `{"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"ARCHIVE LOAD TRANSACTION ` + id + `"}`
	for _, raw := range []string{`{}`, `{"limit":32,"offset":2560}`} {
		if _, err := DecodeLoadBalanceHistoryInput("transactions", []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := DecodeLoadBalanceHistoryInput("archive-transaction", []byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`null`, `[]`, `{} {}`, `{"limit":33}`, `{"limit":"16"}`, `{"limit":null}`, `{"offset":2561}`, `{"offset":-1}`, `{"port":0}`, `{"health_check":null}`, `{"limit":1,"limit":2}`} {
		if _, err := DecodeLoadBalanceHistoryInput("transactions", []byte(raw)); err == nil {
			t.Fatal("invalid raw accepted", raw)
		}
	}
	for _, raw := range []string{`{}`, strings.Replace(valid, "ARCHIVE LOAD TRANSACTION", "ARCHIVE LOAD TRANSACTION ", 1), valid[:len(valid)-1] + `,"domain":""}`, valid[:len(valid)-1] + `,"resource_id":"` + id + `"}`, strings.Replace(valid, sha, strings.ToUpper(sha), 1), strings.Replace(valid, id, "../bad", 1)} {
		if _, err := DecodeLoadBalanceHistoryInput("archive-transaction", []byte(raw)); err == nil {
			t.Fatal("invalid archive accepted", raw)
		}
	}
}

func TestLoadBalanceHistoryInternalInputCannotInheritGenericForm(t *testing.T) {
	id := strings.Repeat("a", 32)
	in := AppModuleInput{ResourceID: id, ExpectedSHA: strings.Repeat("b", 64), Confirm: "ARCHIVE LOAD TRANSACTION " + id}
	for _, edit := range []func(*AppModuleInput){func(v *AppModuleInput) { v.Domain = "other.example.test" }, func(v *AppModuleInput) { v.HealthCheck = &LoadBalanceHTTPHealth{} }, func(v *AppModuleInput) { v.Enabled = true }, func(v *AppModuleInput) { v.Nodes = []AppUpstream{} }, func(v *AppModuleInput) { v.Limit = 16 }, func(v *AppModuleInput) { v.Password = "private" }} {
		v := in
		edit(&v)
		if ValidateLoadBalanceHistoryInput("archive-transaction", v) == nil {
			t.Fatal("inherited business fields accepted")
		}
	}
	for _, action := range []string{"transactions", "archive-transaction"} {
		if !ValidAppModuleAction("load-balance", action) {
			t.Fatal("action hidden", action)
		}
	}
	encoded, _ := json.Marshal(in)
	if _, err := DecodeLoadBalanceHistoryInput("archive-transaction", encoded); err == nil {
		t.Fatal("generic serialized form accepted its unrelated default fields")
	}
}

func TestLoadBalanceHistoryHTTPAuthorizationAndExactForwarding(t *testing.T) {
	store := testStore(t)
	master := accessUser(t, store, "lb-history-master", "", nil)
	viewer := accessUser(t, store, "lb-history-viewer", "viewer", []string{"software"})
	operator := accessUser(t, store, "lb-history-operator", "operator", nil)
	a, err := NewServer(store, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var lastBody []byte
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"status":{"installed":true}}`
		if r.Method == "POST" {
			lastBody, _ = io.ReadAll(r.Body)
			body = `{"load_transactions":[],"configuration_changed":false}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	request := func(route, body, csrf, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", route, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", a.Config.Origin, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var result accountSession
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()[0], result.CSRF
	}
	admin, token := login(master.Username)
	for _, name := range []string{viewer.Username, operator.Username} {
		cookie, csrf := login(name)
		for _, action := range []string{"transactions", "archive-transaction"} {
			before := calls
			w := request("/api/app-modules/load-balance/"+action, "{}", csrf, a.Config.Origin, cookie)
			if w.Code != 403 || calls != before {
				t.Fatal("non-admin history authority reached executor", action, w.Code, calls-before)
			}
		}
	}
	for _, identity := range []struct {
		cookie       *http.Cookie
		csrf, origin string
	}{{admin, "wrong", a.Config.Origin}, {admin, token, "https://foreign.invalid"}, {nil, token, a.Config.Origin}} {
		before := calls
		w := request("/api/app-modules/load-balance/transactions", "{}", identity.csrf, identity.origin, identity.cookie)
		if w.Code < 400 || calls != before {
			t.Fatal("invalid session/CSRF/origin reached executor", w.Code)
		}
	}
	id := strings.Repeat("a", 32)
	sha := strings.Repeat("b", 64)
	for action, body := range map[string]string{"transactions": `{"limit":16,"offset":0}`, "archive-transaction": `{"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"ARCHIVE LOAD TRANSACTION ` + id + `"}`} {
		before := calls
		w := request("/api/app-modules/load-balance/"+action, body, token, a.Config.Origin, admin)
		if w.Code != 200 || calls != before+2 {
			t.Fatal("bounded authorized route not forwarded", w.Code, w.Body.String())
		}
		var want, got map[string]json.RawMessage
		json.Unmarshal([]byte(body), &want)
		json.Unmarshal(lastBody, &got)
		if len(got) != len(want) {
			t.Fatal("generic input defaults leaked across Core/executor boundary", string(lastBody))
		}
		for key, value := range want {
			if string(got[key]) != string(value) {
				t.Fatal("closed forwarded input changed", key)
			}
		}
	}
	for _, body := range []string{`{"limit":16,"port":0}`, `{"offset":0,"offset":1}`, `null`, `{"health_check":null}`} {
		before := calls
		w := request("/api/app-modules/load-balance/transactions", body, token, a.Config.Origin, admin)
		if w.Code != 400 || calls != before {
			t.Fatal("invalid raw body reached executor", body, w.Code, calls-before)
		}
	}
}
