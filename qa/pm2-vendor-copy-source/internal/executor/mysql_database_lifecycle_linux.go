//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Only the low-level SQL helpers accept a per-database identity. Account API
// entrypoints still require core.ValidDatabaseAccount and their own manifest.
func validMySQLScopedIdentity(a core.DatabaseAccount) bool {
	if core.ValidDatabaseAccount(a) {
		return true
	}
	if !core.ValidID(a.ID) || a.Username != "db_"+a.ID[:20] || a.Role != "manager" || len(a.DatabaseIDs) != 1 || a.DatabaseIDs[0] != a.ID {
		return false
	}
	a.Username = "app_" + a.ID[:20]
	return core.ValidDatabaseAccount(a)
}
func normalizeLifecycleDatabase(d core.Database) core.Database {
	if d.Revision == 0 {
		d.Revision = 1
	}
	// Older successful create/migration jobs left their initial status in the
	// root identity manifest. Core delivery and actual SQL scope are checked too.
	if d.Status == "creating" || d.Status == "migrating" {
		d.Status = "ready"
	}
	return d
}
func readLifecycleDatabase(s core.DatabaseServer, id string) (core.Database, error) {
	var d core.Database
	if !core.ValidDatabaseServer(s) || !core.ValidID(id) {
		return d, errors.New("无效数据库身份")
	}
	dir, e := importRoot(mysqlConfig(s.ID) + "/databases")
	if e != nil {
		return d, e
	}
	defer dir.Close()
	f, e := openImportFile(dir, id+".json")
	if e != nil {
		return d, e
	}
	defer f.Close()
	if e = json.NewDecoder(io.LimitReader(f, 32768)).Decode(&d); e != nil {
		return d, e
	}
	d = normalizeLifecycleDatabase(d)
	if d.ID != id || d.ServerID != s.ID || !core.ValidDatabaseName(d.Name) || d.Username != "db_"+id[:20] || d.Revision < 1 || (d.LastJobID != "" && !core.ValidID(d.LastJobID)) {
		return d, errors.New("数据库清单归属无效")
	}
	return d, nil
}
func databaseScopedIdentity(d core.Database) core.DatabaseAccount {
	return core.DatabaseAccount{ID: d.ID, ServerID: d.ServerID, Name: d.Name, Username: d.Username, Role: "manager", DatabaseIDs: []string{d.ID}, Enabled: true, Status: d.Status, Revision: d.Revision}
}
func readDatabaseLifecycleCredential(s core.DatabaseServer, d core.Database) (mysqlCredential, error) {
	var c mysqlCredential
	if d.ServerID != s.ID || !core.ValidID(d.ID) || d.Username != "db_"+d.ID[:20] {
		return c, errors.New("数据库凭据归属无效")
	}
	dir, e := importRoot(mysqlConfig(s.ID) + "/databases")
	if e != nil {
		return c, e
	}
	defer dir.Close()
	f, e := openImportFile(dir, d.ID+".credential.json")
	if e != nil {
		return c, e
	}
	defer f.Close()
	if e = json.NewDecoder(io.LimitReader(f, 4096)).Decode(&c); e != nil {
		return c, e
	}
	if c.Username != d.Username || len(c.Password) != 64 || !core.ValidID(c.Password[:32]) || !core.ValidID(c.Password[32:]) {
		return c, errors.New("数据库私有凭据无效")
	}
	return c, nil
}
func sameLifecycleDatabase(a, b core.Database) bool {
	return a.ID == b.ID && a.ServerID == b.ServerID && a.Name == b.Name && a.Username == b.Username && a.CreatedAt == b.CreatedAt && a.Status == b.Status && a.Revision == b.Revision && a.LastJobID == b.LastJobID
}
func databaseLifecycleReferences(ctx context.Context, s core.DatabaseServer, d core.Database) ([]core.DatabaseAccountReference, error) {
	refs := []core.DatabaseAccountReference{}
	if !validMySQLScopedIdentity(databaseScopedIdentity(d)) || d.ServerID != s.ID {
		return nil, errors.New("数据库归属无效")
	}
	entries, e := os.ReadDir(mysqlConfig(s.ID) + "/accounts")
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			return nil, errors.New("账号清单目录含无法核对的记录")
		}
		m, e := readMySQLAccount(s.ID, entry.Name())
		if e != nil {
			return nil, e
		}
		for _, id := range m.Account.DatabaseIDs {
			if id == d.ID {
				kind := "account"
				if m.Account.Status == "quarantined" {
					dbs, e := ownedAccountDatabases(s, m.Account)
					if e != nil {
						return nil, e
					}
					if e = verifyMySQLAccountGrants(ctx, s, m.Account, dbs, true); e != nil {
						return nil, e
					}
					kind = "recycled_account"
				}
				refs = append(refs, core.DatabaseAccountReference{Kind: kind, Database: d.Name, Name: m.Account.Name})
			}
		}
	}
	definers, e := mysqlAccountDefiners(ctx, s, databaseScopedIdentity(d))
	if e != nil {
		return nil, e
	}
	for _, r := range definers {
		if r.Database != d.Name {
			refs = append(refs, r)
		}
	}
	// External schema/object grants must be removed explicitly. Global server
	// administrators remain administrators; recycling does not revoke their access.
	for _, q := range []string{
		"SELECT JSON_ARRAY(TABLE_SCHEMA,GRANTEE) FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='" + d.Name + "' AND GRANTEE NOT IN (CONCAT(QUOTE('" + d.Username + "'),'@',QUOTE('localhost')),CONCAT(QUOTE('" + d.Username + "'),'@',QUOTE('127.0.0.1'))) GROUP BY TABLE_SCHEMA,GRANTEE LIMIT 50;",
		"SELECT JSON_ARRAY(Db,CONCAT(User,'@',Host)) FROM mysql.tables_priv WHERE Db='" + d.Name + "' AND User<>'" + d.Username + "' LIMIT 50;",
		"SELECT JSON_ARRAY(Db,CONCAT(User,'@',Host)) FROM mysql.columns_priv WHERE Db='" + d.Name + "' AND User<>'" + d.Username + "' LIMIT 50;",
		"SELECT JSON_ARRAY(Db,CONCAT(User,'@',Host)) FROM mysql.procs_priv WHERE Db='" + d.Name + "' AND User<>'" + d.Username + "' LIMIT 50;",
	} {
		raw, e := mysqlQuery(ctx, s, q+"\n")
		if e != nil {
			return nil, e
		}
		if raw == "" {
			continue
		}
		for _, line := range strings.Split(raw, "\n") {
			var v []string
			if json.Unmarshal([]byte(line), &v) != nil || len(v) != 2 {
				return nil, errors.New("实际数据库授权引用无法解析")
			}
			refs = append(refs, core.DatabaseAccountReference{Kind: "grant", Database: v[0], Name: v[1]})
		}
	}
	return refs, nil
}
func verifyDatabaseIdentityBoundary(ctx context.Context, s core.DatabaseServer, d core.Database) error {
	user := d.Username
	hosts, e := mysqlQuery(ctx, s, "SELECT Host FROM mysql.user WHERE User='"+user+"' ORDER BY Host;\n")
	if e != nil {
		return e
	}
	if hosts != "127.0.0.1\nlocalhost" {
		return errors.New("每库应用账号的连接来源已变化")
	}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		grantee := "CONCAT(QUOTE('" + user + "'),'@',QUOTE('" + host + "'))"
		x, e := mysqlQuery(ctx, s, "SELECT (SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE="+grantee+" AND (PRIVILEGE_TYPE<>'USAGE' OR IS_GRANTABLE<>'NO'))+(SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE="+grantee+" AND (TABLE_SCHEMA<>'"+d.Name+"' OR IS_GRANTABLE<>'NO'));\n")
		if e != nil {
			return e
		}
		if x != "0" {
			return errors.New("每库应用账号含额外的全局、跨库或可转授权权限")
		}
	}
	x, e := mysqlQuery(ctx, s, "SELECT (SELECT COUNT(*) FROM mysql.role_edges WHERE TO_USER='"+user+"')+(SELECT COUNT(*) FROM mysql.proxies_priv WHERE User='"+user+"')+(SELECT COUNT(*) FROM mysql.global_grants WHERE USER='"+user+"')+(SELECT COUNT(*) FROM mysql.tables_priv WHERE User='"+user+"' AND Db<>'"+d.Name+"')+(SELECT COUNT(*) FROM mysql.columns_priv WHERE User='"+user+"' AND Db<>'"+d.Name+"')+(SELECT COUNT(*) FROM mysql.procs_priv WHERE User='"+user+"' AND Db<>'"+d.Name+"');\n")
	if e != nil {
		return e
	}
	if x != "0" {
		return errors.New("每库应用账号含模型外的角色、代理或跨库权限")
	}
	exists, e := mysqlQuery(ctx, s, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+d.Name+"';\n")
	if e != nil {
		return e
	}
	if exists != "1" {
		return errors.New("实际数据库不存在，禁止按空库恢复")
	}
	return nil
}
func requireDatabaseLifecycleClear(ctx context.Context, s core.DatabaseServer, d core.Database) error {
	if e := verifyDatabaseIdentityBoundary(ctx, s, d); e != nil {
		return e
	}
	refs, e := databaseLifecycleReferences(ctx, s, d)
	if e != nil {
		return e
	}
	for _, r := range refs {
		if r.Kind != "recycled_account" {
			return errors.New("数据库仍有使用中的账号、外部授权或跨库定义者引用，请先处理依赖")
		}
	}
	return nil
}
func runDatabaseLifecycle(ctx context.Context, op core.DatabaseOperation, add func(string)) error {
	if op.PreviousDatabase == nil || !core.ValidID(op.JobID) || op.Database.LastJobID != op.JobID {
		return errors.New("缺少数据库原状态或任务身份")
	}
	old := *op.PreviousDatabase
	desired := op.Database
	expectedStatus := "ready"
	targetStatus := "quarantined"
	if op.Action == "recover_database" {
		expectedStatus = "quarantined"
		targetStatus = "ready"
	} else if op.Action != "quarantine_database" {
		return errors.New("数据库回收操作无效")
	}
	expected := old
	expected.Revision++
	expected.Status = targetStatus
	expected.LastJobID = op.JobID
	if old.Status != expectedStatus || !sameLifecycleDatabase(expected, desired) || desired.ServerID != op.Server.ID {
		return errors.New("数据库修订或操作范围不匹配")
	}
	actual, e := readLifecycleDatabase(op.Server, desired.ID)
	if e != nil {
		return e
	}
	if sameLifecycleDatabase(actual, desired) {
		if e = verifyMySQLAccountGrants(ctx, op.Server, databaseScopedIdentity(actual), []core.Database{actual}, actual.Status == "quarantined"); e != nil {
			return e
		}
		folder, e := os.Open(mysqlConfig(op.Server.ID) + "/databases")
		if e != nil {
			return e
		}
		defer folder.Close()
		if e = folder.Sync(); e != nil {
			return e
		}
		add("数据库回收或恢复已完成，实际授权及清单持久化核对通过")
		return nil
	}
	if !sameLifecycleDatabase(actual, old) {
		return errors.New("数据库原清单已变化，拒绝覆盖")
	}
	if e = requireDatabaseLifecycleClear(ctx, op.Server, actual); e != nil {
		return e
	}
	credential, e := readDatabaseLifecycleCredential(op.Server, actual)
	if e != nil {
		return e
	}
	rollback := func(cause error) error {
		add("数据库状态未提交，开始恢复：" + cause.Error())
		restoreCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if er := applyMySQLAccount(restoreCtx, op.Server, databaseScopedIdentity(actual), []core.Database{actual}, credential, false, false); er != nil {
			return errors.New("每库应用账号尚未完全恢复；数据、凭据与原任务均保留")
		}
		add("已恢复原每库账号权限、密码和回收状态；实际数据始终保留")
		return errors.New("数据库回收或恢复未提交，已恢复原访问状态")
	}
	if e = applyMySQLAccount(ctx, op.Server, databaseScopedIdentity(desired), []core.Database{desired}, credential, false, false); e != nil {
		return rollback(e)
	}
	if e = requireDatabaseLifecycleClear(ctx, op.Server, desired); e != nil {
		return rollback(e)
	}
	file := mysqlConfig(op.Server.ID) + "/databases/" + desired.ID + ".json"
	if e = writeJSON(file, desired); e != nil {
		current, er := readLifecycleDatabase(op.Server, desired.ID)
		if er == nil && sameLifecycleDatabase(current, desired) {
			return errors.New("数据库状态已应用，但清单持久化未确认；请核对原任务重试")
		}
		if er != nil || !sameLifecycleDatabase(current, actual) {
			return errors.New("数据库清单状态不明确，保留数据与凭据供原任务核对")
		}
		return rollback(e)
	}
	if desired.Status == "quarantined" {
		add("数据库已移入回收站：每库账号登录已锁定且授权撤销，数据、名称和备份仍保留")
	} else {
		add("数据库已恢复：原数据与原密码保留，每库应用账号认证和权限核对通过")
	}
	return nil
}
func databaseLifecycleRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/databases/removal-plan", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ServerID   string `json:"server_id"`
			DatabaseID string `json:"database_id"`
			Revision   int64  `json:"revision"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		s, e := readMySQL(in.ServerID)
		if e != nil {
			respond(w, 409, map[string]string{"error": "实例不可读取"})
			return
		}
		d, e := readLifecycleDatabase(s.Server, in.DatabaseID)
		if e != nil || d.Revision != in.Revision || (d.Status != "ready" && d.Status != "quarantined") {
			respond(w, 409, map[string]string{"error": "数据库版本变化或清单尚未交付"})
			return
		}
		plan := core.DatabaseRemovalPlan{DatabaseID: d.ID, Revision: d.Revision, Status: d.Status, Accounts: []core.DatabaseAccount{}, BlockedReasons: []string{}}
		plan.References, e = databaseLifecycleReferences(r.Context(), s.Server, d)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		for _, ref := range plan.References {
			if ref.Kind != "recycled_account" {
				plan.BlockedReasons = append(plan.BlockedReasons, "仍有使用中的账号、外部授权或跨库定义者引用；请先处理依赖")
				break
			}
		}
		if e = verifyDatabaseIdentityBoundary(r.Context(), s.Server, d); e != nil {
			plan.BlockedReasons = append(plan.BlockedReasons, e.Error())
		}
		x, e := mysqlQuery(r.Context(), s.Server, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER='"+d.Username+"';\n")
		if e == nil {
			plan.Connections, e = strconv.Atoi(x)
		}
		if e != nil {
			respond(w, 409, map[string]string{"error": "无法核对每库账号连接数"})
			return
		}
		respond(w, 200, plan)
	})
}
