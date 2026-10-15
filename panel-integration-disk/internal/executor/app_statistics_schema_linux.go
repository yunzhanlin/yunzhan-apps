//go:build linux

package executor

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type statisticsSchemaObject struct {
	name, kind, table, statement string
	version                      int
}

// One contract supplies both initialization DDL and read-only verification.
// SQLite stores CREATE without IF NOT EXISTS; exact normalized definitions
// bind primary keys, defaults, indexes and the archive CASCADE relationship.
var statisticsSchemaObjects = []statisticsSchemaObject{
	{"access_rows", "table", "access_rows", "CREATE TABLE access_rows(seq INTEGER PRIMARY KEY,site TEXT NOT NULL,stamp INTEGER NOT NULL,ip TEXT NOT NULL,path TEXT NOT NULL,status INTEGER NOT NULL,seconds REAL NOT NULL,bot INTEGER NOT NULL,payload TEXT NOT NULL)", 1},
	{"access_streams", "table", "access_streams", "CREATE TABLE access_streams(site TEXT NOT NULL,identity TEXT NOT NULL,name TEXT NOT NULL,offset INTEGER NOT NULL,anchor TEXT NOT NULL,size INTEGER NOT NULL,seen INTEGER NOT NULL,blocked INTEGER NOT NULL DEFAULT 0,invalid INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(site,identity))", 1},
	{"access_retention", "table", "access_retention", "CREATE TABLE access_retention(site TEXT PRIMARY KEY,evicted INTEGER NOT NULL DEFAULT 0)", 1},
	{"access_site_time", "index", "access_rows", "CREATE INDEX access_site_time ON access_rows(site,stamp,seq)", 1},
	{"access_time", "index", "access_rows", "CREATE INDEX access_time ON access_rows(stamp)", 1},
	{"sqlite_autoindex_access_streams_1", "index", "access_streams", "", 1},
	{"sqlite_autoindex_access_retention_1", "index", "access_retention", "", 1},
	{"access_receipts", "table", "access_receipts", "CREATE TABLE access_receipts(site TEXT NOT NULL,request_id TEXT NOT NULL,payload_sha TEXT NOT NULL,stamp INTEGER NOT NULL,PRIMARY KEY(site,request_id))", 2},
	{"access_archives", "table", "access_archives", "CREATE TABLE access_archives(site TEXT NOT NULL,identity TEXT NOT NULL,metadata TEXT NOT NULL,digest TEXT NOT NULL,state INTEGER NOT NULL,evidence_sha TEXT NOT NULL,PRIMARY KEY(site,identity),FOREIGN KEY(site,identity) REFERENCES access_streams(site,identity) ON DELETE CASCADE)", 2},
	{"access_receipt_time", "index", "access_receipts", "CREATE INDEX access_receipt_time ON access_receipts(stamp)", 2},
	{"sqlite_autoindex_access_receipts_1", "index", "access_receipts", "", 2},
	{"sqlite_autoindex_access_archives_1", "index", "access_archives", "", 2},
}

func statisticsSchemaStatements(version int) []string {
	statements := []string{}
	for _, object := range statisticsSchemaObjects {
		if object.version > version || object.statement == "" {
			continue
		}
		prefix := "CREATE TABLE "
		if object.kind == "index" {
			prefix = "CREATE INDEX "
		}
		statements = append(statements, strings.Replace(object.statement, prefix, prefix+"IF NOT EXISTS ", 1))
	}
	return statements
}

func statisticsSchemaSQL(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func validateStatisticsSchemaObjects(ctx context.Context, db *sql.DB, version int) error {
	expected := map[string]statisticsSchemaObject{}
	for _, object := range statisticsSchemaObjects {
		if object.version <= version {
			expected[object.name] = object
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT name,type,tbl_name,sql FROM sqlite_master WHERE tbl_name IN ('access_rows','access_streams','access_retention','access_receipts','access_archives') LIMIT 33")
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var name, kind, table string
		var statement sql.NullString
		if err = rows.Scan(&name, &kind, &table, &statement); err != nil {
			return err
		}
		object, ok := expected[name]
		if !ok || seen[name] || len(statement.String) > 8192 || kind != object.kind || table != object.table || statement.Valid != (object.statement != "") || statisticsSchemaSQL(statement.String) != statisticsSchemaSQL(object.statement) {
			return errors.New("统计历史表、索引、默认值或外键定义发生非受管变更，未执行迁移或报告就绪")
		}
		seen[name] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("统计历史完整结构定义缺失，未报告就绪")
	}
	return nil
}
