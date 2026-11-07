package core

import (
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func TestSQLImportMigrationExistingSnapshot(t *testing.T) {
	source := os.Getenv("PANEL_IMPORT_MIGRATION_SNAPSHOT")
	if source == "" {
		t.Skip("explicit private earlier-schema snapshot is checked in the Linux development VM")
	}
	f, e := os.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	copyPath := filepath.Join(t.TempDir(), "panel.db")
	dest, e := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = io.Copy(dest, f)
	dest.Close()
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", copyPath)
	if e != nil {
		t.Fatal(e)
	}
	var version int
	if e = db.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); e != nil || (version != 9 && version != 10 && version != 11 && version != 12 && version != 13 && version != 14) {
		t.Fatal("requires schema 9, 10, 11, 12, 13 or 14", version, e)
	}
	names, e := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_migrations' ORDER BY name`)
	if e != nil {
		t.Fatal(e)
	}
	tables := []string{}
	for names.Next() {
		var name string
		if e = names.Scan(&name); e != nil {
			t.Fatal(e)
		}
		tables = append(tables, name)
	}
	names.Close()
	contents := func(db *sql.DB) map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, table := range tables {
			rows, e := db.Query(`SELECT * FROM "` + table + `" ORDER BY rowid`)
			if e != nil {
				t.Fatal(e)
			}
			cols, _ := rows.Columns()
			records := [][]any{}
			for rows.Next() {
				values := make([]any, len(cols))
				ptrs := make([]any, len(cols))
				for i := range values {
					ptrs[i] = &values[i]
				}
				if e = rows.Scan(ptrs...); e != nil {
					t.Fatal(e)
				}
				records = append(records, values)
			}
			if e = rows.Err(); e != nil {
				t.Fatal(e)
			}
			rows.Close()
			raw, e := json.Marshal(records)
			if e != nil {
				t.Fatal(e)
			}
			out[table] = Hash(string(raw))
		}
		return out
	}
	expectedVersion := 19
	if value := os.Getenv("PANEL_MIGRATION_EXPECT_VERSION"); value != "" {
		expectedVersion, e = strconv.Atoi(value)
		if e != nil {
			t.Fatal(e)
		}
	}
	before := contents(db)
	db.Close()
	s, e := OpenStore(copyPath)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	after := contents(s.DB)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing table content changed")
	}
	if e = s.DB.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); e != nil || version != expectedVersion {
		t.Fatal("new migration missing", version, e)
	}
	var integrity string
	s.DB.QueryRow("PRAGMA integrity_check").Scan(&integrity)
	if integrity != "ok" {
		t.Fatal(integrity)
	}
	t.Logf("schema migration preserved all %d existing table hashes", len(tables))
}
