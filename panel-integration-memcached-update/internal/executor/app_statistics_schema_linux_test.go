//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStatisticsSchemaExactDefinitionsMatchInitializerAndRejectDDLDrift(t *testing.T) {
	for _, shape := range []string{"valid", "missing-index", "unknown-unique-index", "missing-cascade", "changed-default"} {
		t.Run(shape, func(t *testing.T) {
			s, original, _ := statisticsLogTransactionFixture(t)
			base := &Service{Config: s.Config}
			db, err := base.openStatisticsHistorySchema(context.Background(), 2)
			if err != nil {
				t.Fatal(err)
			}
			query := ""
			switch shape {
			case "missing-index":
				query = "DROP INDEX access_site_time"
			case "unknown-unique-index":
				query = "CREATE UNIQUE INDEX owned_external ON access_rows(path)"
			case "missing-cascade":
				query = "DROP TABLE access_archives; CREATE TABLE access_archives(site TEXT NOT NULL,identity TEXT NOT NULL,metadata TEXT NOT NULL,digest TEXT NOT NULL,state INTEGER NOT NULL,evidence_sha TEXT NOT NULL,PRIMARY KEY(site,identity))"
			case "changed-default":
				query = "DROP TABLE access_streams; CREATE TABLE access_streams(site TEXT NOT NULL,identity TEXT NOT NULL,name TEXT NOT NULL,offset INTEGER NOT NULL,anchor TEXT NOT NULL,size INTEGER NOT NULL,seen INTEGER NOT NULL,blocked INTEGER NOT NULL DEFAULT 1,invalid INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(site,identity))"
			}
			if query != "" {
				if _, err = db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			path := filepath.Join(base.moduleDir("website-statistics-v2"), "access.sqlite")
			before, _ := os.ReadFile(path)
			version, err := base.statisticsHistorySchemaReadOnly(context.Background())
			if (err == nil) != (shape == "valid") || shape == "valid" && version != 2 {
				t.Fatal("schema contract", shape, version, err)
			}
			if shape != "valid" {
				var calls []string
				statisticsLogTestCommands(t, s, "success", &calls)
				base.Config = s.Config
				if err = base.updateSoftware(context.Background(), "website-statistics-v2", "2.5.0", func(string) {}); err == nil {
					t.Fatal("DDL drift reached migration")
				}
				if len(calls) != 0 {
					t.Fatal("DDL drift reached native mutation", calls)
				}
			}
			after, _ := os.ReadFile(path)
			manifest, _ := os.ReadFile(filepath.Join(base.moduleDir("website-statistics-v2"), "installed.json"))
			if !bytes.Equal(before, after) || !bytes.Equal(original, manifest) {
				t.Fatal("readonly refusal changed original data/identity")
			}
		})
	}
}
