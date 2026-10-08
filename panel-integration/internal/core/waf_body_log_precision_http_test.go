package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWAFBodyLogGovernancePreservesExactIntegerEvidence(t *testing.T) {
	s := testStore(t)
	accessUser(t, s, "admin", "admin", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	// These values cannot be represented exactly by float64. Forwarding them
	// through a map[string]any corrupts the digest-bound plan's observation.
	payload := `{"available":true,"record":{"mtime_nano":1791477273579389626,"inode":9007199254740993,"device":18446744073709551615,"signed_min":-9223372036854775808},"sha256":"` + strings.Repeat("a", 64) + `"}`
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(r.URL.Path, "/v1/software/nginx-waf/body-log/") || r.URL.RawQuery != "" {
			t.Fatal("unexpected privileged path", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
	})}}
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"access-test-password-long"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", a.Config.Origin)
	logged := httptest.NewRecorder()
	a.ServeHTTP(logged, login)
	if logged.Code != 200 {
		t.Fatal(logged.Code, logged.Body.String())
	}
	var auth accountSession
	if err := json.Unmarshal(logged.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	sha := strings.Repeat("a", 64)
	for _, test := range []struct{ method, path, body string }{
		{"GET", "retention", ""}, {"GET", "rotation", ""}, {"GET", "archives", ""}, {"GET", "archives/" + id, ""},
		{"POST", "rotate", `{}`},
		{"POST", "retention/retain", `{"sha256":"` + sha + `","acknowledge_unknown_deletion_not_repeated":true}`},
		{"POST", "rotation/retain", `{"sha256":"` + sha + `","acknowledge_unknown_rotation_not_repeated":true}`},
		{"POST", "index-stages/" + id + "/retain", `{"sha256":"` + sha + `","acknowledge_uncommitted_index_not_applied":true}`},
		{"POST", "archives/" + id + "/retain", `{"index_sha256":"` + sha + `","snapshot_sha256":"` + sha + `","snapshot_missing":false,"acknowledge_unknown_rotation_and_incomplete_snapshot":true}`},
		{"POST", "archives/" + id + "/remove", `{"sha256":"` + sha + `","acknowledge_bounded_export_and_permanent_removal":true}`},
	} {
		t.Run(test.method+"/"+test.path, func(t *testing.T) {
			req := httptest.NewRequest(test.method, "/api/software/nginx-waf/body-log/"+test.path, strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", a.Config.Origin)
			req.Header.Set("X-CSRF-Token", auth.CSRF)
			req.AddCookie(logged.Result().Cookies()[0])
			out := httptest.NewRecorder()
			a.ServeHTTP(out, req)
			if out.Code != 200 || strings.TrimSpace(out.Body.String()) != payload {
				t.Fatal("integer evidence changed in API transport", out.Code, out.Body.String())
			}
		})
	}
}
