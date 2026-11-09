package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Fixtures deliberately include security material and an old retained event.
// Faults must not partially delete either, nor prune history before commit.
func appUserTransactionFixture(t *testing.T) (*Server, identity, identity) {
	t.Helper()
	s := testStore(t)
	actor := accessUser(t, s, "atomic-owner", "admin", nil)
	target := accessUser(t, s, "atomic-reader", "viewer", []string{"files"})
	// Generate the genuine private account key before adding encrypted-record
	// fixture bytes. A missing key with existing material must stay a hard error.
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO sessions VALUES(?,?,?,?,?)`, []any{Hash("owned-user-session"), target.ID, "owned-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()}},
		{`INSERT INTO account_security VALUES(?,X'010203',7,X'040506',19)`, []any{target.ID}},
		{`INSERT INTO account_recovery VALUES(?,? ,11)`, []any{target.ID, Hash("owned-recovery")}},
		{`INSERT INTO account_profiles VALUES(?,'owned@example.invalid')`, []any{target.ID}},
		{`INSERT INTO app_module_events VALUES(?,'user-manager','run','old-owner','succeeded','2000-01-01T00:00:00Z')`, []any{ID()}},
		{`INSERT INTO app_module_events VALUES(?,'platform-ops','run','other-owner','succeeded','2000-01-01T00:00:00Z')`, []any{ID()}},
	} {
		if _, err := s.DB.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return a, actor, target
}

func appUserTables(t *testing.T, s *Store, tables ...string) []byte {
	return appUserTablesExceptSession(t, s, "", tables...)
}

// HTTP authentication legitimately touches only the actor's activity time.
// Compare every target session byte; do not confuse that actor heartbeat with
// a partially committed account operation at a wall-clock second boundary.
func appUserTablesExceptSession(t *testing.T, s *Store, actorID string, tables ...string) []byte {
	t.Helper()
	if len(tables) == 0 {
		tables = []string{"users", "app_user_roles", "app_user_menus", "sessions", "account_security", "account_recovery", "account_profiles", "app_module_events", "audit_logs"}
	}
	all := map[string][][]any{}
	for _, table := range tables {
		query, args := `SELECT * FROM `+table, []any{}
		if table == "sessions" && actorID != "" {
			query += ` WHERE user_id<>?`
			args = append(args, actorID)
		}
		rows, err := s.DB.Query(query+` ORDER BY rowid`, args...)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		all[table] = [][]any{}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			all[table] = append(all[table], values)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func appUserInput(action string) AppModuleInput {
	in := AppModuleInput{Username: "atomic-reader", Role: "operator", MenuIDs: []string{"files"}, ExpectedRevision: 1}
	if action == "create" {
		in.Username = "atomic-created"
		in.Password = "OWNED-ATOMIC-CREATE-secret-1234"
	} else if action == "update" {
		in.Password = "OWNED-ATOMIC-UPDATE-secret-5678"
	}
	return in
}

func TestAppUserTransactionFaultsRetainAllOriginalRows(t *testing.T) {
	for _, action := range []string{"create", "update", "revoke", "delete"} {
		for name, trigger := range map[string]string{
			"success-event":     `BEFORE INSERT ON app_module_events WHEN NEW.module_id='user-manager' AND NEW.outcome='succeeded'`,
			"history-retention": `BEFORE DELETE ON app_module_events WHEN OLD.module_id='user-manager'`,
			"success-audit":     `BEFORE INSERT ON audit_logs WHEN NEW.target='user-manager' AND NEW.result='succeeded'`,
		} {
			t.Run(action+"/"+name, func(t *testing.T) {
				a, actor, _ := appUserTransactionFixture(t)
				if _, err := a.Store.DB.Exec(`CREATE TRIGGER owned_failure ` + trigger + ` BEGIN SELECT RAISE(ABORT,'owned-test-fault'); END`); err != nil {
					t.Fatal(err)
				}
				before := appUserTables(t, a.Store)
				if out, err := a.manageAppUsers(context.Background(), actor, action, appUserInput(action)); err == nil || out != nil {
					t.Fatal("fault returned committed success", action, name)
				}
				if !bytes.Equal(before, appUserTables(t, a.Store)) {
					t.Fatal("account/security/session/history/audit changed despite transaction fault", action, name)
				}
			})
		}
	}
	for _, item := range []struct{ action, trigger string }{
		{"create", `BEFORE INSERT ON app_user_roles`},
		{"create", `BEFORE INSERT ON app_user_menus`},
		{"update", `BEFORE UPDATE ON users`},
		{"update", `BEFORE DELETE ON sessions`},
		{"update", `BEFORE INSERT ON app_user_menus`},
		{"revoke", `BEFORE DELETE ON sessions`},
		{"delete", `BEFORE DELETE ON account_security`},
		{"delete", `BEFORE DELETE ON users`},
	} {
		t.Run(item.action+"/"+item.trigger, func(t *testing.T) {
			a, actor, _ := appUserTransactionFixture(t)
			if _, err := a.Store.DB.Exec(`CREATE TRIGGER owned_failure ` + item.trigger + ` BEGIN SELECT RAISE(ABORT,'owned-test-fault'); END`); err != nil {
				t.Fatal(err)
			}
			before := appUserTables(t, a.Store)
			if _, err := a.manageAppUsers(context.Background(), actor, item.action, appUserInput(item.action)); err == nil {
				t.Fatal("failed business write succeeded")
			}
			if !bytes.Equal(before, appUserTables(t, a.Store)) {
				t.Fatal("partial business transaction retained")
			}
		})
	}
}

func TestAppUserTransactionSuccessPublishesExactlyOneRedactedOutcome(t *testing.T) {
	for _, action := range []string{"create", "update", "revoke", "delete"} {
		t.Run(action, func(t *testing.T) {
			a, actor, target := appUserTransactionFixture(t)
			in := appUserInput(action)
			out, err := a.manageAppUsers(context.Background(), actor, action, in)
			if err != nil || out == nil {
				t.Fatal(err)
			}
			var events, audits, old, other int
			for query, dest := range map[string]*int{
				`SELECT count(*) FROM app_module_events WHERE module_id='user-manager' AND outcome='succeeded'`:               &events,
				`SELECT count(*) FROM audit_logs WHERE target='user-manager' AND result='succeeded'`:                          &audits,
				`SELECT count(*) FROM app_module_events WHERE module_id='user-manager' AND created_at='2000-01-01T00:00:00Z'`: &old,
				`SELECT count(*) FROM app_module_events WHERE module_id='platform-ops'`:                                       &other,
			} {
				if err := a.Store.DB.QueryRow(query).Scan(dest); err != nil {
					t.Fatal(err)
				}
			}
			if events != 1 || audits != 1 || old != 0 || other != 1 {
				t.Fatal("wrong event/audit/retention boundary", events, audits, old, other)
			}
			raw := appUserTables(t, a.Store, "app_module_events", "audit_logs")
			for _, secret := range []string{"secret-1234", "secret-5678", "owned-user-session", "owned-recovery", "owned@example.invalid", "password_hash", "010203", "owned-csrf", target.Username} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("sensitive input leaked to operation summary")
				}
			}
			if action == "create" || action == "update" {
				var id string
				var hash []byte
				if err := a.Store.DB.QueryRow(`SELECT id,password_hash FROM users WHERE username=?`, in.Username).Scan(&id, &hash); err != nil || bcrypt.CompareHashAndPassword(hash, []byte(in.Password)) != nil {
					t.Fatal("successful password not stored as intended bcrypt hash", err)
				}
				access, err := a.Store.UserAccess(id)
				wantRevision := int64(1)
				if action == "update" {
					wantRevision = 2
				}
				if err != nil || access.Role != in.Role || access.Revision != wantRevision || len(access.MenuIDs) != 1 || access.MenuIDs[0] != "files" {
					t.Fatal("successful authorization incorrect", access, err)
				}
			}
			if action != "create" {
				var sessions int
				if err := a.Store.DB.QueryRow(`SELECT count(*) FROM sessions WHERE user_id=?`, target.ID).Scan(&sessions); err != nil || sessions != 0 {
					t.Fatal("old sessions remain valid", err, sessions)
				}
			}
			if action == "delete" {
				for _, table := range []string{"users", "app_user_roles", "app_user_menus", "account_security", "account_recovery", "account_profiles"} {
					key := "user_id"
					if table == "users" {
						key = "id"
					}
					var n int
					if err := a.Store.DB.QueryRow(`SELECT count(*) FROM `+table+` WHERE `+key+`=?`, target.ID).Scan(&n); err != nil || n != 0 {
						t.Fatal("deleted account/security residue", table, n, err)
					}
				}
			}
		})
	}
}

func TestAppUserTransactionCancellationDoesNotWriteOrWaitForPool(t *testing.T) {
	a, actor, _ := appUserTransactionFixture(t)
	for _, action := range []string{"run", "create", "update", "revoke", "delete"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		before := appUserTables(t, a.Store)
		if _, err := a.manageAppUsers(ctx, actor, action, appUserInput(action)); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled operation not rejected", action, err)
		}
		if !bytes.Equal(before, appUserTables(t, a.Store)) {
			t.Fatal("cancelled operation changed storage", action)
		}
	}
	conn, err := a.Store.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.manageAppUsers(ctx, actor, "revoke", appUserInput("revoke")); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("context cancellation waited for occupied single-connection pool")
	}
	conn.Close()
}

func TestAppUserTransactionHTTPNoDuplicateOrPartialFailureAudit(t *testing.T) {
	for _, scenario := range []string{"success", "event-fault", "audit-fault", "failure-audit-fault"} {
		t.Run(scenario, func(t *testing.T) {
			a, actor, _ := appUserTransactionFixture(t)
			var err error
			calls := 0
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/app-modules/user-manager" {
					t.Fatal("business forwarded to executor")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":{"id":"user-manager","installed":true}}`))}, nil
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
			cookie := w.Result().Cookies()[0]
			trigger := ""
			switch scenario {
			case "event-fault":
				trigger = `BEFORE INSERT ON app_module_events WHEN NEW.module_id='user-manager' AND NEW.outcome='succeeded'`
			case "audit-fault":
				trigger = `BEFORE INSERT ON audit_logs WHEN NEW.target='user-manager' AND NEW.result='succeeded'`
			case "failure-audit-fault":
				trigger = `BEFORE INSERT ON audit_logs WHEN NEW.target='user-manager'`
			}
			if trigger != "" {
				if _, err = a.Store.DB.Exec(`CREATE TRIGGER owned_failure ` + trigger + ` BEGIN SELECT RAISE(ABORT,'owned-test-fault'); END`); err != nil {
					t.Fatal(err)
				}
			}
			tables := []string{"users", "app_user_roles", "app_user_menus", "sessions", "account_security", "account_recovery", "account_profiles"}
			before := appUserTablesExceptSession(t, a.Store, actor.ID, tables...)
			out := request("/api/app-modules/user-manager/revoke", `{"username":"atomic-reader","expected_revision":1}`, session.CSRF, cookie)
			var events, audits, succeeded int
			for query, dest := range map[string]*int{
				`SELECT count(*) FROM app_module_events WHERE module_id='user-manager' AND action='revoke'`:  &events,
				`SELECT count(*) FROM audit_logs WHERE target='user-manager' AND action='app-module.revoke'`: &audits,
				`SELECT count(*) FROM audit_logs WHERE target='user-manager' AND result='succeeded'`:         &succeeded,
			} {
				if err = a.Store.DB.QueryRow(query).Scan(dest); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 1 {
				t.Fatal("unexpected executor dispatch", calls)
			}
			if scenario == "success" {
				if out.Code != 200 || events != 1 || audits != 1 || succeeded != 1 {
					t.Fatal("duplicate or absent committed audit", out.Code, events, audits, succeeded)
				}
			} else {
				if out.Code != 409 || succeeded != 0 || !bytes.Equal(before, appUserTablesExceptSession(t, a.Store, actor.ID, tables...)) {
					t.Fatal("HTTP fault changed business", out.Code, succeeded)
				}
				want := 1
				if scenario == "failure-audit-fault" {
					want = 0
					if !strings.Contains(out.Body.String(), "失败审计亦无法保存") {
						t.Fatal("unavailable failure audit hidden")
					}
				}
				if events != want || audits != want {
					t.Fatal("partial failure event/audit", events, audits, want)
				}
			}
		})
	}
}
