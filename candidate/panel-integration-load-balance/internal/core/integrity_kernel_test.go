package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func integrityKernelInputFixture() IntegrityKernelInput {
	site := strings.Repeat("1", 32)
	return IntegrityKernelInput{SiteID: site, ExpectedRevision: 0, ExpectedAppVersion: IntegrityKernelAppVersion, BaselineSHA: strings.Repeat("a", 64), Confirm: "PROTECT SITE " + site}
}

func TestIntegrityKernelHTTPKeepsAuthCSRFActorAndReceiptBoundary(t *testing.T) {
	s := testStore(t)
	master := accessUser(t, s, "kernel-http-admin", "", nil)
	viewer := accessUser(t, s, "kernel-http-viewer", "viewer", nil)
	limited := accessUser(t, s, "kernel-http-limited", "admin", []string{"security"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	input := integrityKernelInputFixture()
	body, _ := json.Marshal(input)
	appSHA := strings.Repeat("b", 64)
	if _, err = s.DB.Exec(`INSERT INTO app_registry_receipts VALUES('website-tamper-proof','website-tamper-proof',?,?,'website-tamper-proof',?)`, IntegrityKernelAppVersion, appSHA, Now()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	wrongReply := false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, "/v1/integrity-kernel/operations/") {
			t.Fatal("unexpected executor call", r.Method, r.URL.Path)
		}
		var request IntegrityKernelRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || ValidateIntegrityKernelRequest(request) != nil || request.ActorID != master.ID || request.AppSHA != appSHA || request.ID != Hash("integrity-kernel-operation-v1\x00" + master.ID + "\x00http-original-key")[:32] {
			t.Fatal("Core changed original request identity", request)
		}
		if wrongReply {
			request.ActorID = ID()
		}
		out := IntegrityKernelOperation{Request: request, RequestSHA: IntegrityKernelRequestSHA(request), Revision: 1, State: "queued"}
		raw, _ := json.Marshal(out)
		return &http.Response{StatusCode: 202, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	request := func(method, path, body, csrf, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var session accountSession
		if json.Unmarshal(w.Body.Bytes(), &session) != nil {
			t.Fatal(w.Body.String())
		}
		return w.Result().Cookies()[0], session.CSRF
	}
	path := "/api/app-modules/website-tamper-proof/kernel/enable"
	if w := request("POST", path, string(body), "", "http-original-key", nil); w.Code != 401 || calls != 0 {
		t.Fatal("anonymous native dispatch", w.Code, calls)
	}
	for _, user := range []identity{viewer, limited} {
		cookie, csrf := login(user.Username)
		if w := request("POST", path, string(body), csrf, "http-original-key", cookie); w.Code != 403 || calls != 0 {
			t.Fatal("limited role dispatched native operation", user.Username, w.Code, calls)
		}
	}
	cookie, csrf := login(master.Username)
	if w := request("POST", path, string(body), "wrong", "http-original-key", cookie); w.Code != 403 || calls != 0 {
		t.Fatal("missing CSRF reached executor", w.Code, calls)
	}
	if w := request("POST", path, string(body), csrf, "", cookie); w.Code != 400 || calls != 0 {
		t.Fatal("missing stable key reached executor", w.Code, calls)
	}
	if w := request("POST", path, strings.TrimSuffix(string(body), "}")+`,"path":"/etc/passwd"}`, csrf, "http-original-key", cookie); w.Code != 400 || calls != 0 {
		t.Fatal("unknown input reached executor", w.Code, calls)
	}
	if w := request("POST", path, string(body), csrf, "http-original-key", cookie); w.Code != 202 || calls != 1 {
		t.Fatal("valid admission failed", w.Code, w.Body.String(), calls)
	}
	wrongReply = true
	if w := request("POST", path, string(body), csrf, "http-original-key", cookie); w.Code != 502 || calls != 2 {
		t.Fatal("foreign actor receipt accepted", w.Code, w.Body.String())
	}
	for _, query := range []string{"", "?site_id=../outside", "?site_id=" + input.SiteID + "&path=/etc", "?site_id=" + input.SiteID + "&site_id=" + input.SiteID} {
		if w := request("GET", "/api/app-modules/website-tamper-proof/kernel"+query, "", "", "", cookie); w.Code != 400 || calls != 2 {
			t.Fatal("unclosed status query reached executor", query, w.Code, calls)
		}
	}
}

func integrityKernelRequestFixture() IntegrityKernelRequest {
	return IntegrityKernelRequest{Format: 1, ID: strings.Repeat("2", 32), ActorID: strings.Repeat("3", 32), AccessRevision: 1, AppSHA: strings.Repeat("b", 64), Action: "enable", Input: integrityKernelInputFixture(), CreatedAt: "2026-11-05T01:02:03Z"}
}

func TestIntegrityKernelClosedInputPreservesExactIdentity(t *testing.T) {
	valid := integrityKernelInputFixture()
	raw, _ := json.Marshal(valid)
	if got, err := DecodeIntegrityKernelInput("enable", raw); err != nil || got != valid {
		t.Fatal(got, err)
	}
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"duplicate", strings.Replace(string(raw), `"site_id":`, `"site_id":"`+valid.SiteID+`","site_id":`, 1)},
		{"case-alias", strings.Replace(string(raw), `"site_id":`, `"Site_ID":`, 1)},
		{"missing-explicit-empty", strings.Replace(string(raw), `"source_sha":"",`, "", 1)},
		{"null-revision", strings.Replace(string(raw), `"expected_revision":0`, `"expected_revision":null`, 1)},
		{"null-source", strings.Replace(string(raw), `"source_sha":""`, `"source_sha":null`, 1)},
		{"unknown", strings.TrimSuffix(string(raw), "}") + `,"path":"/etc/passwd"}`},
		{"nested", strings.Replace(string(raw), `"expected_revision":0`, `"expected_revision":{}`, 1)},
		{"fraction", strings.Replace(string(raw), `"expected_revision":0`, `"expected_revision":1.25`, 1)},
		{"integer-string", strings.Replace(string(raw), `"expected_revision":0`, `"expected_revision":"0"`, 1)},
		{"array", "[" + string(raw) + "]"},
		{"trailing", string(raw) + ` {}`},
		{"oversize", string(raw) + strings.Repeat(" ", 4097)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeIntegrityKernelInput("enable", []byte(tc.raw)); err == nil {
				t.Fatal("unclosed Root input accepted", tc.name)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*IntegrityKernelInput)
	}{
		{"wrong-site", func(v *IntegrityKernelInput) { v.SiteID = "../site" }},
		{"negative-revision", func(v *IntegrityKernelInput) { v.ExpectedRevision = -1 }},
		{"overflow-revision", func(v *IntegrityKernelInput) { v.ExpectedRevision = 1 << 60 }},
		{"old-app", func(v *IntegrityKernelInput) { v.ExpectedAppVersion = "1.4.1" }},
		{"future-app", func(v *IntegrityKernelInput) { v.ExpectedAppVersion = "1.5.1" }},
		{"alias-app", func(v *IntegrityKernelInput) { v.ExpectedAppVersion = "1.5.0-compat1" }},
		{"uppercase-sha", func(v *IntegrityKernelInput) { v.BaselineSHA = strings.Repeat("A", 64) }},
		{"short-sha", func(v *IntegrityKernelInput) { v.BaselineSHA = "a" }},
		{"foreign-confirm", func(v *IntegrityKernelInput) { v.Confirm = "PROTECT SITE " + ID() }},
		{"release-identity", func(v *IntegrityKernelInput) { v.SourceOperation = ID(); v.SourceSHA = strings.Repeat("c", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := valid
			tc.change(&input)
			if ValidateIntegrityKernelInput("enable", input) == nil {
				t.Fatal("invalid kernel enable accepted")
			}
		})
	}
	release := valid
	release.BaselineSHA = ""
	release.SourceOperation = ID()
	release.SourceSHA = strings.Repeat("c", 64)
	release.Confirm = "RELEASE SITE " + release.SiteID
	if err := ValidateIntegrityKernelInput("release", release); err != nil {
		t.Fatal(err)
	}
	if ValidateIntegrityKernelInput("enable", release) == nil || ValidateIntegrityKernelInput("release", valid) == nil || ValidateIntegrityKernelInput("restore", release) == nil {
		t.Fatal("actions borrowed another workflow")
	}
}

func TestIntegrityKernelWorkerAuthorityBindsActorGrantAndSignedReceipt(t *testing.T) {
	s := testStore(t)
	u := accessUser(t, s, "kernel-admin", "", nil)
	request := integrityKernelRequestFixture()
	request.ActorID = u.ID
	if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at) VALUES('website-tamper-proof','website-tamper-proof',?,?, 'website-tamper-proof',?)`, IntegrityKernelAppVersion, request.AppSHA, Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateIntegrityKernelAuthority(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"actor", "grant-revision", "receipt-sha", "app-version"} {
		t.Run(field, func(t *testing.T) {
			changed := request
			switch field {
			case "actor":
				changed.ActorID = ID()
			case "grant-revision":
				changed.AccessRevision++
			case "receipt-sha":
				changed.AppSHA = strings.Repeat("f", 64)
			case "app-version":
				changed.Input.ExpectedAppVersion = "1.4.1"
			}
			if s.ValidateIntegrityKernelAuthority(context.Background(), changed) == nil {
				t.Fatal("stale/foreign authority accepted")
			}
		})
	}
	limited := accessUser(t, s, "kernel-limited", "admin", []string{"security"})
	request.ActorID = limited.ID
	if s.ValidateIntegrityKernelAuthority(context.Background(), request) == nil {
		t.Fatal("limited administrator acquired wider Root operation")
	}
	request.ActorID = u.ID
	if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'null',2)", u.ID); err != nil {
		t.Fatal(err)
	}
	if s.ValidateIntegrityKernelAuthority(context.Background(), request) == nil {
		t.Fatal("revocation/regrant preserved queued authorization")
	}
	request.AccessRevision = 2
	if err := s.ValidateIntegrityKernelAuthority(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("UPDATE app_registry_receipts SET sha256=? WHERE app_id='website-tamper-proof'", strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if s.ValidateIntegrityKernelAuthority(context.Background(), request) == nil {
		t.Fatal("queued operation borrowed a newer receipt")
	}
}

func TestIntegrityKernelOriginalOutcomeCannotBeRelabelled(t *testing.T) {
	request := integrityKernelRequestFixture()
	if IntegrityKernelRequestSHA(request) != "a145ba1a816c689231e3b288930a83498a79f114e2d3dec4e7d35c0bb201b6ce" {
		t.Fatal("cross-language original request digest changed")
	}
	if Hash("integrity-kernel-operation-v1\x00" + request.ActorID + "\x00original-key")[:32] != "bc7926e49fcda298a324b77c289b9cd5" {
		t.Fatal("original actor/key identity changed")
	}
	out := IntegrityKernelOperation{Request: request, RequestSHA: IntegrityKernelRequestSHA(request), Revision: 1, State: "queued"}
	if !ValidIntegrityKernelOperation(out) {
		t.Fatal(out)
	}
	changed := out
	changed.Request.ActorID = ID()
	if ValidIntegrityKernelOperation(changed) {
		t.Fatal("request changed without original digest")
	}
	changed = out
	changed.State = "succeeded"
	changed.FinishedAt = Now()
	changed.Error = "original unknown result"
	if ValidIntegrityKernelOperation(changed) {
		t.Fatal("unknown result masqueraded as success")
	}
	changed = out
	changed.State = "needs-attention"
	changed.Error = "original start without verified final outcome"
	if !ValidIntegrityKernelOperation(changed) {
		t.Fatal("unknown operation could not be reported")
	}
	changed = out
	changed.Revision = 2
	if ValidIntegrityKernelOperation(changed) {
		t.Fatal("new revision invented")
	}
}

func TestIntegrityKernelSoftwareVersionCannotRelabelAnOlderHandler(t *testing.T) {
	for _, validate := range []func(string, string) error{ValidateSoftwareUpdate, ValidateSoftwareInstallVersion} {
		for _, version := range []string{"1.4.1", IntegrityKernelAppVersion} {
			if err := validate("website-tamper-proof", version); err != nil {
				t.Fatal(version, err)
			}
		}
		for _, version := range []string{"1.5.0-compat1", "1.5.0+build", "1.5.1", "2.0.0", "01.5.0", "future"} {
			if validate("website-tamper-proof", version) == nil {
				t.Fatal("unimplemented kernel version or alias accepted", version)
			}
		}
	}
}
