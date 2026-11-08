package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func platformTransactionFixture(t *testing.T) (*Server, identity) {
	t.Helper()
	a, actor, _ := appUserTransactionFixture(t)
	encrypted, err := encryptCredential(a.accountSecretKey, "app-host:owned-host", []byte(strings.Repeat("1", 64)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Store.DB.Exec(`INSERT INTO app_platform_hosts VALUES('owned-host','https://original.example.invalid',?,'2001-01-01T00:00:00Z')`, encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Store.DB.Exec(`INSERT INTO app_platform_tokens VALUES(?,'2001-01-01T00:00:00Z')`, Hash(strings.Repeat("1", 64))); err != nil {
		t.Fatal(err)
	}
	return a, actor
}

func platformInput(t *testing.T, a *Server, action string) AppModuleInput {
	t.Helper()
	in := AppModuleInput{ResourceID: "owned-host", URL: "https://updated.example.invalid", Token: strings.Repeat("1", 64)}
	if action == "add" || action == "remove" {
		var address, created string
		var encrypted []byte
		if err := a.Store.DB.QueryRow(`SELECT url,token,created_at FROM app_platform_hosts WHERE id='owned-host'`).Scan(&address, &encrypted, &created); err != nil {
			t.Fatal(err)
		}
		in.ExpectedSHA = platformHostIdentity(in.ResourceID, address, encrypted, created)
	}
	return in
}

func platformTables(t *testing.T, s *Store) []byte {
	t.Helper()
	return appUserTables(t, s, "app_platform_hosts", "app_platform_tokens", "app_module_events", "audit_logs")
}

func TestPlatformTransactionFaultsPreserveHostsSecretsTokensAndHistory(t *testing.T) {
	for _, action := range []string{"add", "remove", "issue-token", "revoke-token"} {
		triggers := map[string]string{
			"success-event":     `BEFORE INSERT ON app_module_events WHEN NEW.module_id='platform-ops' AND NEW.outcome='succeeded'`,
			"history-retention": `BEFORE DELETE ON app_module_events WHEN OLD.module_id='platform-ops'`,
			"success-audit":     `BEFORE INSERT ON audit_logs WHEN NEW.target='platform-ops' AND NEW.result='succeeded'`,
		}
		switch action {
		case "add":
			triggers["business-insert"] = `BEFORE INSERT ON app_platform_hosts`
			triggers["business-update"] = `BEFORE UPDATE ON app_platform_hosts`
		case "remove":
			triggers["business-delete"] = `BEFORE DELETE ON app_platform_hosts`
		case "issue-token":
			triggers["business-insert"] = `BEFORE INSERT ON app_platform_tokens`
		case "revoke-token":
			triggers["business-delete"] = `BEFORE DELETE ON app_platform_tokens`
		}
		for name, trigger := range triggers {
			t.Run(action+"/"+name, func(t *testing.T) {
				a, actor := platformTransactionFixture(t)
				if _, err := a.Store.DB.Exec(`CREATE TRIGGER owned_failure ` + trigger + ` BEGIN SELECT RAISE(ABORT,'owned-platform-test-fault'); END`); err != nil {
					t.Fatal(err)
				}
				before := platformTables(t, a.Store)
				out, err := a.platformOperation(context.Background(), actor, action, platformInput(t, a, action))
				if err == nil || out != nil {
					t.Fatal("fault exposed success or newly generated token", action, name)
				}
				if !bytes.Equal(before, platformTables(t, a.Store)) {
					t.Fatal("host/ciphertext/token/history/audit changed despite fault")
				}
			})
		}
	}
}

func TestPlatformTransactionSuccessHasOneRedactedCommittedOutcome(t *testing.T) {
	for _, action := range []string{"add", "remove", "issue-token", "revoke-token"} {
		t.Run(action, func(t *testing.T) {
			a, actor := platformTransactionFixture(t)
			out, err := a.platformOperation(context.Background(), actor, action, platformInput(t, a, action))
			if err != nil || out == nil {
				t.Fatal(err)
			}
			var events, audits, old, other int
			for query, dest := range map[string]*int{
				`SELECT count(*) FROM app_module_events WHERE module_id='platform-ops' AND outcome='succeeded'`: &events,
				`SELECT count(*) FROM audit_logs WHERE target='platform-ops' AND result='succeeded'`:            &audits,
				`SELECT count(*) FROM app_module_events WHERE module_id='platform-ops' AND created_at<'2002'`:   &old,
				`SELECT count(*) FROM app_module_events WHERE module_id='user-manager' AND created_at<'2002'`:   &other,
			} {
				if err = a.Store.DB.QueryRow(query).Scan(dest); err != nil {
					t.Fatal(err)
				}
			}
			if events != 1 || audits != 1 || old != 0 || other != 1 {
				t.Fatal("absent/duplicate event or cross-module retention", events, audits, old, other)
			}
			if bytes.Contains(appUserTables(t, a.Store, "app_module_events", "audit_logs"), []byte(strings.Repeat("1", 64))) {
				t.Fatal("plaintext token in audit")
			}
			switch action {
			case "issue-token":
				token, ok := out.(map[string]any)["token"].(string)
				if !ok || len(token) != 64 {
					t.Fatal("missing committed token")
				}
				var count int
				if err = a.Store.DB.QueryRow(`SELECT count(*) FROM app_platform_tokens WHERE token_hash=?`, Hash(token)).Scan(&count); err != nil || count != 1 {
					t.Fatal("token returned before commit")
				}
				if bytes.Contains(platformTables(t, a.Store), []byte(token)) {
					t.Fatal("new token stored in plaintext")
				}
			case "add":
				var address, created string
				var encrypted []byte
				if err = a.Store.DB.QueryRow(`SELECT url,token,created_at FROM app_platform_hosts WHERE id='owned-host'`).Scan(&address, &encrypted, &created); err != nil {
					t.Fatal(err)
				}
				secret, err := decryptCredential(a.accountSecretKey, "app-host:owned-host", encrypted)
				if err != nil || string(secret) != strings.Repeat("1", 64) || address != "https://updated.example.invalid" || created != "2001-01-01T00:00:00Z" {
					t.Fatal("host update destroyed identity or encrypted grant")
				}
			case "remove", "revoke-token":
				table := "app_platform_hosts"
				if action == "revoke-token" {
					table = "app_platform_tokens"
				}
				var count int
				if err = a.Store.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
					t.Fatal("business removal uncommitted")
				}
			}
		})
	}
}

func TestPlatformCapacityKeepsExistingRecordsAndAllowsFullHostUpdate(t *testing.T) {
	a, actor := platformTransactionFixture(t)
	for i := 1; i < 12; i++ {
		if _, err := a.Store.DB.Exec(`INSERT INTO app_platform_hosts VALUES(?, 'https://owned.example.invalid', X'010203', ?)`, fmt.Sprintf("owned-host-%02d", i), Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.platformOperation(context.Background(), actor, "add", platformInput(t, a, "add")); err != nil {
		t.Fatal("full inventory prevented existing update", err)
	}
	before := platformTables(t, a.Store)
	in := platformInput(t, a, "add")
	in.ResourceID = "owned-thirteenth"
	in.ExpectedSHA = ""
	if out, err := a.platformOperation(context.Background(), actor, "add", in); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
		t.Fatal("capacity silently evicted or accepted 13th host")
	}
	if _, err := a.Store.DB.Exec(`INSERT INTO app_platform_hosts VALUES('owned-corrupt-extra','https://owned.example.invalid',X'01',?)`, Now()); err != nil {
		t.Fatal(err)
	}
	before = platformTables(t, a.Store)
	for _, action := range []string{"run", "add"} {
		if out, err := a.platformOperation(context.Background(), actor, action, platformInput(t, a, action)); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
			t.Fatal("corrupt overflow produced partial complete inventory")
		}
	}
	for i := 1; i < 128; i++ {
		if _, err := a.Store.DB.Exec(`INSERT INTO app_platform_tokens VALUES(?,?)`, Hash(fmt.Sprint("owned-cap-token-", i)), Now()); err != nil {
			t.Fatal(err)
		}
	}
	before = platformTables(t, a.Store)
	if out, err := a.platformOperation(context.Background(), actor, "issue-token", AppModuleInput{}); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
		t.Fatal("token capacity dropped old grant or leaked new token")
	}
	if _, err := a.platformOperation(context.Background(), actor, "revoke-token", platformInput(t, a, "revoke-token")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.platformOperation(context.Background(), actor, "issue-token", AppModuleInput{}); err != nil {
		t.Fatal("explicit revoke did not release capacity", err)
	}
	var count int
	if err := a.Store.DB.QueryRow(`SELECT count(*) FROM app_platform_tokens`).Scan(&count); err != nil || count != 128 {
		t.Fatal("capacity wrong", count, err)
	}
}

func TestPlatformCancellationAndCurrentAuthorizationAreFailClosed(t *testing.T) {
	a, actor := platformTransactionFixture(t)
	for _, action := range []string{"run", "add", "remove", "issue-token", "revoke-token"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		before := platformTables(t, a.Store)
		if out, err := a.platformOperation(ctx, actor, action, platformInput(t, a, action)); !errors.Is(err, context.Canceled) || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
			t.Fatal("cancellation misreported or wrote", action, err)
		}
	}
	in := platformInput(t, a, "remove")
	conn, err := a.Store.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.platformOperation(ctx, actor, "remove", in); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("cancellation waited for occupied pool")
	}
	conn.Close()
	for _, item := range []struct {
		role  string
		menus []string
	}{{"viewer", []string{"files"}}, {"admin", []string{"files"}}} {
		raw, _ := json.Marshal(item.menus)
		if _, err = a.Store.DB.Exec(`UPDATE app_user_roles SET role=? WHERE user_id=?`, item.role, actor.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = a.Store.DB.Exec(`INSERT INTO app_user_menus VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET menu_ids=excluded.menu_ids`, actor.ID, string(raw)); err != nil {
			t.Fatal(err)
		}
		before := platformTables(t, a.Store)
		for _, action := range []string{"run", "add", "remove", "issue-token", "revoke-token"} {
			if out, err := a.platformOperation(context.Background(), actor, action, platformInput(t, a, action)); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
				t.Fatal("stale actor bypassed current role/menu", action)
			}
		}
	}
}

func TestPlatformHostSnapshotRejectsStaleOverwriteDeleteAndResurrection(t *testing.T) {
	a, actor := platformTransactionFixture(t)
	old := platformInput(t, a, "add")
	for _, missing := range []string{"", strings.Repeat("f", 64), "invalid"} {
		in := old
		in.ExpectedSHA = missing
		before := platformTables(t, a.Store)
		if out, err := a.platformOperation(context.Background(), actor, "add", in); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
			t.Fatal("unselected/stale host update overwrote current grant")
		}
	}
	out, err := a.platformOperation(context.Background(), actor, "add", old)
	if err != nil {
		t.Fatal(err)
	}
	current := out.(map[string]any)["expected_sha"].(string)
	if current == old.ExpectedSHA || current != platformInput(t, a, "remove").ExpectedSHA {
		t.Fatal("new snapshot identity not current committed record")
	}
	for _, action := range []string{"add", "remove"} {
		before := platformTables(t, a.Store)
		if out, err := a.platformOperation(context.Background(), actor, action, old); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
			t.Fatal("old identity overwrote or deleted newer host", action)
		}
	}
	fresh := platformInput(t, a, "remove")
	if _, err = a.platformOperation(context.Background(), actor, "remove", fresh); err != nil {
		t.Fatal(err)
	}
	before := platformTables(t, a.Store)
	if out, err := a.platformOperation(context.Background(), actor, "add", fresh); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
		t.Fatal("stale absent host was silently recreated")
	}
	create := old
	create.ExpectedSHA = ""
	if _, err = a.platformOperation(context.Background(), actor, "add", create); err != nil {
		t.Fatal("explicit new identity could not create", err)
	}
	before = platformTables(t, a.Store)
	if out, err := a.platformOperation(context.Background(), actor, "remove", fresh); err == nil || out != nil || !bytes.Equal(before, platformTables(t, a.Store)) {
		t.Fatal("previous lifetime identity deleted newly recreated host")
	}
}

func TestPlatformTransactionHTTPNoDuplicateOrPartialFailureAudit(t *testing.T) {
	for _, scenario := range []string{"success", "event-fault", "audit-fault", "failure-audit-fault"} {
		t.Run(scenario, func(t *testing.T) {
			a, actor := platformTransactionFixture(t)
			calls := 0
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/app-modules/platform-ops" {
					t.Fatal("business forwarded to executor")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":{"id":"platform-ops","installed":true}}`))}, nil
			})}}
			request := func(path, raw, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", path, strings.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", a.Config.Origin)
				r.Header.Set("X-CSRF-Token", csrf)
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			w := request("/api/login", `{"username":"`+actor.Username+`","password":"access-test-password-long"}`, "", nil)
			var session accountSession
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &session) != nil || session.CSRF == "" {
				t.Fatal("fixture login", w.Code)
			}
			trigger := ""
			switch scenario {
			case "event-fault":
				trigger = `BEFORE INSERT ON app_module_events WHEN NEW.module_id='platform-ops' AND NEW.outcome='succeeded'`
			case "audit-fault":
				trigger = `BEFORE INSERT ON audit_logs WHEN NEW.target='platform-ops' AND NEW.result='succeeded'`
			case "failure-audit-fault":
				trigger = `BEFORE INSERT ON audit_logs WHEN NEW.target='platform-ops'`
			}
			if trigger != "" {
				if _, err := a.Store.DB.Exec(`CREATE TRIGGER owned_failure ` + trigger + ` BEGIN SELECT RAISE(ABORT,'owned-platform-fault'); END`); err != nil {
					t.Fatal(err)
				}
			}
			before := appUserTables(t, a.Store, "app_platform_hosts", "app_platform_tokens")
			out := request("/api/app-modules/platform-ops/issue-token", `{}`, session.CSRF, w.Result().Cookies()[0])
			var events, audits, succeeded int
			for query, dest := range map[string]*int{`SELECT count(*) FROM app_module_events WHERE module_id='platform-ops' AND action='issue-token'`: &events, `SELECT count(*) FROM audit_logs WHERE target='platform-ops' AND action='app-module.issue-token'`: &audits, `SELECT count(*) FROM audit_logs WHERE target='platform-ops' AND result='succeeded'`: &succeeded} {
				if err := a.Store.DB.QueryRow(query).Scan(dest); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 1 {
				t.Fatal("unexpected executor dispatch", calls)
			}
			if scenario == "success" {
				if out.Code != 200 || events != 1 || audits != 1 || succeeded != 1 {
					t.Fatal("duplicate or absent success", out.Code, events, audits, succeeded)
				}
			} else {
				if out.Code != 409 || succeeded != 0 || !bytes.Equal(before, appUserTables(t, a.Store, "app_platform_hosts", "app_platform_tokens")) || strings.Contains(out.Body.String(), `"token":`) {
					t.Fatal("HTTP fault committed business or leaked token", out.Code)
				}
				want := 1
				if scenario == "failure-audit-fault" {
					want = 0
					if !strings.Contains(out.Body.String(), "失败审计亦无法保存") {
						t.Fatal("failure audit unavailable hidden")
					}
				}
				if events != want || audits != want {
					t.Fatal("partial failure event/audit", events, audits)
				}
			}
		})
	}
}
