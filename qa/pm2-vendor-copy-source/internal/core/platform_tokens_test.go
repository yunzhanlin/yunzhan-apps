package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlatformPublicTokenInventoryRevokesLostSecretWithoutAuthenticatingDigest(t *testing.T) {
	a, actor := platformTransactionFixture(t)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v1/overview" || r.Method != "GET" {
			t.Fatal("unexpected agent executor operation")
		}
		raw, _ := json.Marshal(platformHealthFixtureNow())
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	issued, err := a.platformOperation(context.Background(), actor, "issue-token", AppModuleInput{})
	if err != nil {
		t.Fatal(err)
	}
	token := issued.(map[string]any)["token"].(string)
	id := issued.(map[string]any)["token_id"].(string)
	if id != Hash(token) || id == token {
		t.Fatal("public identity not digest")
	}
	list, err := a.platformOperation(context.Background(), actor, "token-list", AppModuleInput{})
	if err != nil {
		t.Fatal(err)
	}
	items := list.(map[string]any)["tokens"].([]map[string]any)
	if len(items) != 2 {
		t.Fatal("incomplete actual token inventory")
	}
	raw, _ := json.Marshal(list)
	if bytes.Contains(raw, []byte(token)) {
		t.Fatal("stored plaintext recovered")
	}
	agent := func(bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/platform/agent", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	for _, bad := range []string{id, "A" + token[1:], token + " ", "", strings.Repeat("z", 64)} {
		if out := agent(bad); out.Code != 401 || calls != 0 {
			t.Fatal("public/malformed bearer authenticated", out.Code)
		}
	}
	if out := agent(token); out.Code != 200 || calls != 1 {
		t.Fatal("actual retained grant rejected", out.Code)
	}
	out, err := a.platformOperation(context.Background(), actor, "revoke-token", AppModuleInput{TokenID: id})
	if err != nil || out.(map[string]any)["token_id"] != id || out.(map[string]any)["already_absent"] != false {
		t.Fatal("lost secret could not be revoked by public ID", err)
	}
	if out := agent(token); out.Code != 401 || calls != 1 {
		t.Fatal("revoked bearer still dispatched overview")
	}
	out, err = a.platformOperation(context.Background(), actor, "revoke-token", AppModuleInput{TokenID: id})
	if err != nil || out.(map[string]any)["already_absent"] != true {
		t.Fatal("absent grant not reported truthfully", err)
	}
}

func platformHealthFixtureNow() map[string]any {
	return map[string]any{"arch": "amd64", "cpu_available": false, "cpu_percent": nil}
}

func TestPlatformTokenInventoryRejectsCorruptionAndRevocationAmbiguity(t *testing.T) {
	for _, scenario := range []string{"bad-id", "bad-date", "overflow"} {
		t.Run(scenario, func(t *testing.T) {
			a, actor := platformTransactionFixture(t)
			switch scenario {
			case "bad-id":
				if _, err := a.Store.DB.Exec(`UPDATE app_platform_tokens SET token_hash='invalid'`); err != nil {
					t.Fatal(err)
				}
			case "bad-date":
				if _, err := a.Store.DB.Exec(`UPDATE app_platform_tokens SET created_at='invalid'`); err != nil {
					t.Fatal(err)
				}
			case "overflow":
				for i := 0; i < 128; i++ {
					if _, err := a.Store.DB.Exec(`INSERT INTO app_platform_tokens VALUES(?,?)`, Hash(strings.Repeat("x", i+1)), Now()); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := platformTables(t, a.Store)
			if out, err := a.platformOperation(context.Background(), actor, "token-list", AppModuleInput{}); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
				t.Fatal("corrupt inventory silently normalized, truncated or accepted")
			}
		})
	}
	a, actor := platformTransactionFixture(t)
	for _, in := range []AppModuleInput{{}, {Token: "invalid"}, {TokenID: "invalid"}, {Token: strings.Repeat("1", 64), TokenID: Hash(strings.Repeat("1", 64))}} {
		before := platformTables(t, a.Store)
		if out, err := a.platformOperation(context.Background(), actor, "revoke-token", in); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
			t.Fatal("ambiguous grant removal wrote")
		}
	}
	for _, trigger := range []string{`BEFORE DELETE ON app_platform_tokens`, `BEFORE INSERT ON audit_logs WHEN NEW.target='platform-ops' AND NEW.result='succeeded'`} {
		a, actor := platformTransactionFixture(t)
		if _, err := a.Store.DB.Exec(`CREATE TRIGGER owned_failure ` + trigger + ` BEGIN SELECT RAISE(ABORT,'owned-token-id-fault'); END`); err != nil {
			t.Fatal(err)
		}
		before := platformTables(t, a.Store)
		if out, err := a.platformOperation(context.Background(), actor, "revoke-token", AppModuleInput{TokenID: Hash(strings.Repeat("1", 64))}); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
			t.Fatal("public-ID revocation did not atomically roll back")
		}
	}
}
