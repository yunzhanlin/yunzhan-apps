//go:build linux

package executor

import (
	"local/panel/internal/core"
	"testing"
)

func TestDatabaseScopedIdentityAndLegacyMetadata(t *testing.T) {
	d := core.Database{ID: core.ID(), ServerID: core.ID(), Name: "app_data", Status: "creating"}
	d.Username = "db_" + d.ID[:20]
	normalized := normalizeLifecycleDatabase(d)
	if normalized.Status != "ready" || normalized.Revision != 1 || normalized.LastJobID != "" {
		t.Fatal("legacy manifest migration")
	}
	a := databaseScopedIdentity(normalized)
	if !validMySQLScopedIdentity(a) || core.ValidDatabaseAccount(a) {
		t.Fatal("per-database scope leaked into account API")
	}
	bad := a
	bad.Role = "readonly"
	if validMySQLScopedIdentity(bad) {
		t.Fatal("per-database identity allowed role rewrite")
	}
	bad = a
	bad.DatabaseIDs = []string{core.ID()}
	if validMySQLScopedIdentity(bad) {
		t.Fatal("per-database identity allowed foreign schema")
	}
	d.Status = "quarantined"
	d.Revision = 4
	if !sameLifecycleDatabase(normalizeLifecycleDatabase(d), d) {
		t.Fatal("recycled metadata normalized to ready")
	}
	badDB := d
	badDB.Revision++
	if sameLifecycleDatabase(d, badDB) {
		t.Fatal("revision ignored")
	}
}
