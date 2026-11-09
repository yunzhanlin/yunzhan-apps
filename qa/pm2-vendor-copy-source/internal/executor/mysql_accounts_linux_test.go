//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMySQLAccountGrantBoundaries(t *testing.T) {
	server, id, dbid := core.ID(), core.ID(), core.ID()
	a := core.DatabaseAccount{ID: id, ServerID: server, Name: "reader", Username: "app_" + id[:20], DatabaseIDs: []string{dbid}, Role: "readonly", Revision: 1, Enabled: true}
	db := core.Database{ID: dbid, ServerID: server, Name: "app_data", Status: "ready"}
	cred := mysqlCredential{Username: a.Username, Password: core.Token()}
	sql, e := accountGrantSQL(a, []core.Database{db}, cred, true)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(sql, " ON *.*") || strings.Contains(sql, "IDENTIFIED BY ''") || strings.Count(sql, "GRANT SELECT, SHOW VIEW ON `app_data`.*") != 2 || strings.Count(sql, "ACCOUNT LOCK") != 4 {
		t.Fatal("grant exceeded target scope")
	}
	if len(accountPrivileges("readonly")) != 2 || len(accountPrivileges("manager")) != 18 {
		t.Fatal("privilege catalog")
	}
	a.Status = "quarantined"
	if sql, e = accountGrantSQL(a, []core.Database{db}, cred, false); e != nil || strings.Contains(sql, "GRANT SELECT") || strings.Count(sql, "REVOKE ALL PRIVILEGES") != 2 {
		t.Fatal("recycled identity retained schema grants", e)
	}
	a.Status = "ready"
	for _, role := range []string{"readwrite", "manager"} {
		a.Role = role
		if _, e = accountGrantSQL(a, []core.Database{db}, cred, false); e != nil {
			t.Fatal(e)
		}
	}
	a.Role = "FILE"
	if _, e = accountGrantSQL(a, []core.Database{db}, cred, false); e == nil {
		t.Fatal("global privilege accepted")
	}
	a.Role = "readonly"
	changed := db
	changed.Name = "app`; DROP USER root; --"
	if _, e = accountGrantSQL(a, []core.Database{changed}, cred, false); e == nil {
		t.Fatal("SQL identifier injection")
	}
	changed = db
	changed.ServerID = core.ID()
	if _, e = accountGrantSQL(a, []core.Database{changed}, cred, false); e == nil {
		t.Fatal("cross-instance grant")
	}
	changed = db
	changed.Status = "importing"
	if _, e = accountGrantSQL(a, []core.Database{changed}, cred, false); e == nil {
		t.Fatal("unpublished import granted")
	}
	cred.Password = strings.Repeat("'", 64)
	if _, e = accountGrantSQL(a, []core.Database{db}, cred, false); e == nil {
		t.Fatal("credential injection")
	}
}

func TestMySQLAccountTransitionBoundaries(t *testing.T) {
	id := core.ID()
	old := core.DatabaseAccount{ID: id, ServerID: core.ID(), Name: "fixture", Username: "app_" + id[:20], Role: "readonly", DatabaseIDs: []string{core.ID()}, Revision: 4, Enabled: true, Status: "ready"}
	a := old
	a.Revision++
	a.Status = "quarantined"
	op := core.DatabaseOperation{Action: "quarantine_account", Account: &a, PreviousAccount: &old}
	if e := validateMySQLAccountTransition(op); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*core.DatabaseAccount){func(a *core.DatabaseAccount) { a.Role = "manager" }, func(a *core.DatabaseAccount) { a.Enabled = false }, func(a *core.DatabaseAccount) { a.Revision = 4 }, func(a *core.DatabaseAccount) { a.DatabaseIDs = []string{core.ID()} }} {
		bad := a
		change(&bad)
		op.Account = &bad
		if e := validateMySQLAccountTransition(op); e == nil {
			t.Fatal("recycle altered the preserved identity state")
		}
	}
	old = a
	a.Status = "ready"
	a.Revision++
	op = core.DatabaseOperation{Action: "restore_account", Account: &a, PreviousAccount: &old}
	if e := validateMySQLAccountTransition(op); e != nil {
		t.Fatal(e)
	}
	op.Action = "enable_account"
	if e := validateMySQLAccountTransition(op); e == nil {
		t.Fatal("enable bypassed explicit restore")
	}
}

// Opt-in acceptance against the two isolated development instances. This verifies
// a drifted table grant is rejected even when schema-level grants still match.
func TestMySQLAccountObjectGrantDriftLive(t *testing.T) {
	raw := os.Getenv("PANEL_ACCOUNT_GRANT_CHECKS")
	if raw == "" {
		t.Skip("dedicated development VM fixtures required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for private development fixtures")
	}
	if _, e := os.Stat("/etc/panel-development-vm"); e != nil {
		t.Fatal(e)
	}
	var fixtures []struct{ Server, Account string }
	if e := json.Unmarshal([]byte(raw), &fixtures); e != nil || len(fixtures) != 2 {
		t.Fatal("expected two version fixtures")
	}
	for _, f := range fixtures {
		t.Run(f.Account, func(t *testing.T) {
			m, e := readMySQLAccount(f.Server, f.Account)
			if e != nil {
				t.Fatal(e)
			}
			a := m.Account
			if a.Role != "readonly" || a.Status != "ready" || !a.Enabled {
				t.Fatal("requires an enabled readonly acceptance account")
			}
			s, e := readMySQL(f.Server)
			if e != nil {
				t.Fatal(e)
			}
			dbs, e := ownedAccountDatabases(s.Server, a)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if e = verifyMySQLAccountGrants(ctx, s.Server, a, dbs, false); e != nil {
				t.Fatal(e)
			}
			if !strings.HasPrefix(dbs[0].Name, "sql_import_") {
				t.Fatal("requires SQL acceptance database")
			}
			object := "`" + dbs[0].Name + "`.`notes`"
			identity := "'" + a.Username + "'@'127.0.0.1'"
			if _, e = mysqlQuery(ctx, s.Server, "GRANT UPDATE ON "+object+" TO "+identity+";\n"); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				restoreCtx, done := context.WithTimeout(context.Background(), time.Minute)
				defer done()
				if _, err := mysqlQuery(restoreCtx, s.Server, "REVOKE UPDATE ON "+object+" FROM "+identity+";\n"); err != nil {
					t.Error(err)
				}
				if err := verifyMySQLAccountGrants(restoreCtx, s.Server, a, dbs, false); err != nil {
					t.Error(err)
				}
			})
			if e = verifyMySQLAccountGrants(ctx, s.Server, a, dbs, false); e == nil || !strings.Contains(e.Error(), "对象级授权") {
				t.Fatalf("object privilege drift not rejected: %v", e)
			}
		})
	}
}
