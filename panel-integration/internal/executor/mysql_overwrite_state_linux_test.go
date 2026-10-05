//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func overwriteStateFixture(t *testing.T) (string, mysqlOverwriteJournal) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root-private Linux fixture")
	}
	base, v, j := releaseFixture(t)
	old := j.Operation.Database
	old.Status = "ready"
	old.Revision = 1
	old.CreatedAt = core.Now()
	op := j.Operation
	op.Action = "overwrite_database"
	op.PreviousDatabase = &old
	op.Database = old
	op.Database.Revision = 2
	op.Database.LastJobID = op.JobID
	v.TargetDatabaseID = old.ID
	v.TargetRevision = old.Revision
	op.Import = &v
	state := mysqlOverwriteJournal{Operation: op, Phase: "prepared", Charset: "utf8mb4", Collation: "utf8mb4_0900_ai_ci", Grants: map[string][]string{"localhost": accountPrivileges("manager"), "127.0.0.1": accountPrivileges("manager")}, UpdatedAt: core.Now()}
	if e := saveOverwriteJournal(base, state); e != nil {
		t.Fatal(e)
	}
	return base, state
}
func TestOverwriteJournalOwnershipAndRecoveryPhases(t *testing.T) {
	base, j := overwriteStateFixture(t)
	if e := transitionOverwrite(base, &j, "importing"); e == nil {
		t.Fatal("backup bypassed")
	}
	c, e := overwriteCredential(base, j.Operation)
	if e != nil {
		t.Fatal(e)
	}
	again, e := overwriteCredential(base, j.Operation)
	if e != nil || again != c {
		t.Fatal("candidate secret regenerated")
	}
	if e = transitionOverwrite(base, &j, "secured"); e != nil {
		t.Fatal(e)
	}
	if e = transitionOverwrite(base, &j, "backup_ready"); e == nil {
		t.Fatal("missing backup accepted")
	}
	j.Backup = core.DatabaseBackup{ID: j.Operation.JobID, ServerID: j.Operation.Server.ID, DatabaseID: j.Operation.Database.ID, Version: "8.4.11", Bytes: 42, SHA256: core.Hash("trusted backup")}
	j.Before = mysqlFingerprint{Rows: 2, Sum: core.Hash("old rows"), Objects: "table:notes:BASE TABLE"}
	if e = transitionOverwrite(base, &j, "backup_ready"); e != nil {
		t.Fatal(e)
	}
	if overwriteRecoveryAction(j.Phase) != "abort" {
		t.Fatal("backup-only phase rewrites data")
	}
	if e = transitionOverwrite(base, &j, "importing"); e != nil {
		t.Fatal(e)
	}
	if overwriteRecoveryAction(j.Phase) != "rollback" {
		t.Fatal("partial import will be published")
	}
	if e = transitionOverwrite(base, &j, "completed"); e == nil {
		t.Fatal("unverified import published")
	}
	if e = transitionOverwrite(base, &j, "rolling_back"); e != nil {
		t.Fatal(e)
	}
	if e = transitionOverwrite(base, &j, "restored"); e != nil {
		t.Fatal(e)
	}
	if overwriteRecoveryAction(j.Phase) != "restore_access" {
		t.Fatal("verified restored data can be overwritten after reopening access")
	}
	if e = transitionOverwrite(base, &j, "rolled_back"); e != nil {
		t.Fatal(e)
	}
	if e = transitionOverwrite(base, &j, "importing"); e == nil {
		t.Fatal("rolled-back upload can reexecute")
	}
	path := filepath.Join(base, j.Operation.JobID+".json")
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = readOverwriteJournal(base, j.Operation.JobID); e == nil {
		t.Fatal("public journal accepted")
	}
}
func TestOverwriteJournalRejectsChangedTargetAndPrivileges(t *testing.T) {
	base, j := overwriteStateFixture(t)
	changed := j
	changed.Operation.Database.Name = "other"
	if e := saveOverwriteJournal(base, changed); e == nil {
		t.Fatal("target identity changed")
	}
	changed = j
	changed.Grants = map[string][]string{"localhost": {"SELECT", "CREATE USER"}, "127.0.0.1": {"SELECT"}}
	if e := saveOverwriteJournal(base, changed); e == nil {
		t.Fatal("global SQL privilege replay allowed")
	}
	changed = j
	changed.Charset = "utf8mb4; DROP DATABASE other"
	if e := saveOverwriteJournal(base, changed); e == nil {
		t.Fatal("SQL charset injection allowed")
	}
	if overwriteRecoveryAction("unknown") != "invalid" {
		t.Fatal("unknown phase accepted")
	}
	// A completed task cannot be rolled back even if an old operation is replayed.
	j.Phase = "completed"
	j.Backup = core.DatabaseBackup{ID: j.Operation.JobID, ServerID: j.Operation.Server.ID, DatabaseID: j.Operation.Database.ID, Version: "8.4.11", Bytes: 42, SHA256: core.Hash("backup")}
	j.Before.Sum = core.Hash("before")
	j.Imported.Sum = core.Hash("after")
	if e := saveOverwriteJournal(base, j); e != nil {
		t.Fatal(e)
	}
	if e := transitionOverwrite(base, &j, "rolling_back"); e == nil {
		t.Fatal("completed database overwritten by old recovery")
	}
}

func TestOverwriteSQLClaimCannotChangeTarget(t *testing.T) {
	base, j := overwriteStateFixture(t)
	v := *j.Operation.Import
	for _, suffix := range []string{".sql", ".json", ".claim.json"} {
		if e := os.Remove(filepath.Join(base, v.ID+suffix)); e != nil {
			t.Fatal(e)
		}
	}
	body := "CREATE TABLE notes(id INT);\n"
	staged, e := stageSQLImport(context.Background(), base, v, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	j.Operation.Import = &staged
	f, e := claimOverwriteSQL(context.Background(), base, j.Operation)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	changed := j.Operation
	changed.JobID = core.ID()
	changed.Database.LastJobID = changed.JobID
	if f, e = claimOverwriteSQL(context.Background(), base, changed); e == nil {
		f.Close()
		t.Fatal("SQL upload reassigned to another overwrite job")
	}
	bad := staged
	bad.TargetRevision++
	if f, e = openSQLImport(context.Background(), base, bad); e == nil {
		f.Close()
		t.Fatal("staged target revision changed")
	}
	if _, e = stageSQLImport(context.Background(), base, bad, strings.NewReader(body)); e == nil {
		t.Fatal("reupload silently changed target revision")
	}
}

func TestOverwriteActualPreflight(t *testing.T) {
	serverID := os.Getenv("PANEL_OVERWRITE_PREFLIGHT_SERVER")
	dbID := os.Getenv("PANEL_OVERWRITE_PREFLIGHT_DATABASE")
	if serverID == "" && dbID == "" {
		t.Skip("explicit existing development fixture required")
	}
	if os.Geteuid() != 0 || !core.ValidID(serverID) || !core.ValidID(dbID) {
		t.Fatal("invalid preflight fixture")
	}
	m, e := readMySQL(serverID)
	if e != nil {
		t.Fatal(e)
	}
	d, e := readLifecycleDatabase(m.Server, dbID)
	if e != nil {
		t.Fatal(e)
	}
	op := core.DatabaseOperation{Action: "overwrite_database", JobID: core.ID(), Server: m.Server, PreviousDatabase: &d, Database: d}
	op.Database.Revision++
	op.Database.LastJobID = op.JobID
	op.Import = &core.DatabaseImport{ID: core.ID(), ServerID: serverID, Name: d.Name, Bytes: 1, SHA256: core.Hash("read-only preflight"), TargetDatabaseID: dbID, TargetRevision: d.Revision}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, e := fingerprintMySQL(ctx, m.Server, d)
	if e != nil {
		t.Fatal(e)
	}
	journal, e := inspectOverwriteTarget(ctx, op, true)
	if e != nil {
		t.Fatal(e)
	}
	if !validOverwriteJournal(journal) {
		t.Fatal("invalid inspected journal")
	}
	after, e := fingerprintMySQL(ctx, m.Server, d)
	if e != nil || before != after {
		t.Fatal("read-only preflight changed database", e)
	}
	t.Log("real version", m.Server.ReleaseID, "charset", journal.Charset, "grants", len(journal.Grants["localhost"]), "data fingerprint unchanged")
}
