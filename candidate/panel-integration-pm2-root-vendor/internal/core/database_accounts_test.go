package core

import (
	"database/sql"
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestDatabaseAccountsScopeAndRevision(t *testing.T) {
	s := testStore(t)
	if e := s.migrateDatabaseAccounts(); e != nil {
		t.Fatal(e)
	}
	r, _ := runtimecatalog.Find("mysql-8.4.11")
	if e := s.RecordInstallation(r, "arm64"); e != nil {
		t.Fatal(e)
	}
	makeServer := func(name string, port int) DatabaseServer {
		v := DatabaseServer{ID: ID(), Name: name, ReleaseID: r.ID, Port: port, Status: "running", CreatedAt: Now()}
		if _, e := s.DB.Exec(`INSERT INTO mysql_servers VALUES(?,?,?,?,?,?)`, v.ID, v.Name, v.ReleaseID, v.Port, v.Status, v.CreatedAt); e != nil {
			t.Fatal(e)
		}
		return v
	}
	server := makeServer("accounts", 13306)
	foreign := makeServer("foreign", 13307)
	makeDB := func(srv DatabaseServer, name, status string) Database {
		d := Database{ID: ID(), ServerID: srv.ID, Name: name, Status: status, CreatedAt: Now()}
		d.Username = "db_" + d.ID[:20]
		if _, e := s.DB.Exec(`INSERT INTO mysql_databases VALUES(?,?,?,?,?,?)`, d.ID, d.ServerID, d.Name, d.Username, d.Status, d.CreatedAt); e != nil {
			t.Fatal(e)
		}
		return d
	}
	first := makeDB(server, "first", "ready")
	second := makeDB(server, "second", "ready")
	other := makeDB(foreign, "other", "ready")
	partial := makeDB(server, "partial", "importing")
	txn := func(f func(*sql.Tx) error) error {
		tx, e := s.DB.Begin()
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = f(tx); e != nil {
			return e
		}
		return tx.Commit()
	}
	op := DatabaseOperation{Action: "create_account", Server: server, Account: &DatabaseAccount{Name: "Reporting", Role: "readonly", DatabaseIDs: []string{second.ID, first.ID}}}
	if e := txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &op) }); e != nil {
		t.Fatal(e)
	}
	if !ValidDatabaseAccount(*op.Account) || op.Account.Username != "app_"+op.Account.ID[:20] || op.Account.Status != "creating" {
		t.Fatal("account identity")
	}
	if e := txn(func(tx *sql.Tx) error { return finishDatabaseAccount(tx, op, DatabaseResult{State: "succeeded"}) }); e != nil {
		t.Fatal(e)
	}
	stored, e := s.DatabaseAccount(op.Account.ID)
	if e != nil || stored.Status != "ready" || !stored.Enabled {
		t.Fatal("account creation", e)
	}
	for _, ids := range [][]string{{other.ID}, {partial.ID}, {first.ID, first.ID}, {}} {
		bad := DatabaseOperation{Action: "create_account", Server: server, Account: &DatabaseAccount{Name: "invalid", Role: "readonly", DatabaseIDs: ids}}
		if e = txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &bad) }); e == nil {
			t.Fatal("out-of-scope or unpublished grant accepted")
		}
	}
	update := DatabaseOperation{Action: "update_account", Server: server, Account: &DatabaseAccount{ID: stored.ID, Revision: stored.Revision, Role: "readwrite", DatabaseIDs: []string{first.ID}}}
	if e = txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &update) }); e != nil {
		t.Fatal(e)
	}
	if update.PreviousAccount == nil || update.PreviousAccount.Role != "readonly" || update.Account.Revision != 2 {
		t.Fatal("previous grants missing")
	}
	if e = txn(func(tx *sql.Tx) error { return finishDatabaseAccount(tx, update, DatabaseResult{State: "succeeded"}) }); e != nil {
		t.Fatal(e)
	}
	stale := DatabaseOperation{Action: "disable_account", Server: server, Account: &stored}
	if e = txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &stale) }); e == nil {
		t.Fatal("stale update allowed")
	}
	ready, _ := s.DatabaseAccount(stored.ID)
	quarantine := DatabaseOperation{Action: "quarantine_account", Server: server, Account: &ready}
	if e = txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &quarantine) }); e != nil {
		t.Fatal(e)
	}
	if quarantine.Account.Status != "quarantined" || !quarantine.Account.Enabled || quarantine.PreviousAccount.Status != "ready" {
		t.Fatal("recycle must preserve original activation and grant metadata")
	}
	if e = txn(func(tx *sql.Tx) error {
		return finishDatabaseAccount(tx, quarantine, DatabaseResult{State: "succeeded"})
	}); e != nil {
		t.Fatal(e)
	}
	archived, _ := s.DatabaseAccount(stored.ID)
	if archived.Status != "quarantined" || archived.Revision != 3 {
		t.Fatal("recycle not committed")
	}
	for _, action := range []string{"enable_account", "disable_account", "rotate_account", "update_account", "quarantine_account"} {
		bad := DatabaseOperation{Action: action, Server: server, Account: &archived}
		if e = txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &bad) }); e == nil {
			t.Fatal("ordinary action bypassed recycle state", action)
		}
	}
	restore := DatabaseOperation{Action: "restore_account", Server: server, Account: &archived}
	if e = txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &restore) }); e != nil {
		t.Fatal(e)
	}
	if e = txn(func(tx *sql.Tx) error { return finishDatabaseAccount(tx, restore, DatabaseResult{State: "succeeded"}) }); e != nil {
		t.Fatal(e)
	}
	ready, _ = s.DatabaseAccount(stored.ID)
	if ready.Status != "ready" || ready.Revision != 4 || !ready.Enabled || ready.Role != "readwrite" {
		t.Fatal("recycle recovery lost metadata")
	}
	fresh, _ := s.DatabaseAccount(stored.ID)
	disable := DatabaseOperation{Action: "disable_account", Server: server, Account: &fresh}
	if e = txn(func(tx *sql.Tx) error { return queueDatabaseAccount(tx, &disable) }); e != nil {
		t.Fatal(e)
	}
	if disable.Account.Enabled {
		t.Fatal("disable did not change desired state")
	}
	if e = txn(func(tx *sql.Tx) error { return finishDatabaseAccount(tx, disable, DatabaseResult{State: "failed"}) }); e != nil {
		t.Fatal(e)
	}
	failed, _ := s.DatabaseAccount(stored.ID)
	if failed.Status != "needs_attention" || failed.Revision != 4 || !failed.Enabled {
		t.Fatal("failed mutation incorrectly committed")
	}
}
