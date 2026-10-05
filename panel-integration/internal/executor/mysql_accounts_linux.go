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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type mysqlAccountManifest struct {
	Account       core.DatabaseAccount `json:"account"`
	LastJobID     string               `json:"last_job_id"`
	CredentialRef string               `json:"credential_ref"`
}

func mysqlAccountDir(server, id string) string {
	return filepath.Join(mysqlConfig(server), "accounts", id)
}
func validAccountCredentialRef(ref string) bool {
	return strings.HasPrefix(ref, "pending-") && strings.HasSuffix(ref, ".json") && core.ValidID(strings.TrimSuffix(strings.TrimPrefix(ref, "pending-"), ".json"))
}
func readMySQLAccount(server, id string) (mysqlAccountManifest, error) {
	var v mysqlAccountManifest
	if !core.ValidID(server) || !core.ValidID(id) {
		return v, errors.New("无效账号标识")
	}
	dir, e := importRoot(mysqlAccountDir(server, id))
	if e != nil {
		return v, e
	}
	defer dir.Close()
	f, e := openImportFile(dir, "manifest.json")
	if e != nil {
		return v, e
	}
	defer f.Close()
	if e = json.NewDecoder(io.LimitReader(f, 32768)).Decode(&v); e != nil {
		return v, e
	}
	if !core.ValidDatabaseAccount(v.Account) || v.Account.ID != id || v.Account.ServerID != server || !core.ValidID(v.LastJobID) || ((v.Account.Status == "ready" || v.Account.Status == "quarantined") && !validAccountCredentialRef(v.CredentialRef)) {
		return v, errors.New("数据库账号清单归属无效")
	}
	return v, nil
}
func accountPrivileges(role string) []string {
	switch role {
	case "readonly":
		return []string{"SELECT", "SHOW VIEW"}
	case "readwrite":
		return []string{"DELETE", "EXECUTE", "INSERT", "SELECT", "SHOW VIEW", "UPDATE"}
	case "manager":
		return []string{"ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROUTINE", "CREATE TEMPORARY TABLES", "CREATE VIEW", "DELETE", "DROP", "EVENT", "EXECUTE", "INDEX", "INSERT", "LOCK TABLES", "REFERENCES", "SELECT", "SHOW VIEW", "TRIGGER", "UPDATE"}
	}
	return nil
}
func validateAccountDatabases(a core.DatabaseAccount, dbs []core.Database) error {
	if !validMySQLScopedIdentity(a) || len(dbs) != len(a.DatabaseIDs) {
		return errors.New("账号或授权范围无效")
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, db := range dbs {
		if !core.ValidID(db.ID) || db.ServerID != a.ServerID || !core.ValidDatabaseName(db.Name) || ids[db.ID] || names[db.Name] || db.Status == "importing" || (db.Status == "quarantined" && a.Status != "quarantined" && a.Username != "db_"+db.ID[:20]) {
			return errors.New("数据库归属、名称或交付状态无效")
		}
		ids[db.ID] = true
		names[db.Name] = true
	}
	for _, id := range a.DatabaseIDs {
		if !ids[id] {
			return errors.New("授权数据库标识不一致")
		}
	}
	return nil
}
func accountGrantSQL(a core.DatabaseAccount, dbs []core.Database, cred mysqlCredential, create bool) (string, error) {
	if e := validateAccountDatabases(a, dbs); e != nil {
		return "", e
	}
	if cred.Username != a.Username || len(cred.Password) != 64 || !core.ValidID(cred.Password[:32]) || !core.ValidID(cred.Password[32:]) {
		return "", errors.New("账号凭据不匹配")
	}
	var out strings.Builder
	for _, host := range []string{"localhost", "127.0.0.1"} {
		identity := "'" + a.Username + "'@'" + host + "'"
		if create {
			out.WriteString("CREATE USER IF NOT EXISTS " + identity + " IDENTIFIED BY '" + cred.Password + "' ACCOUNT LOCK;\n")
		}
		out.WriteString("ALTER USER " + identity + " IDENTIFIED BY '" + cred.Password + "' ACCOUNT LOCK;\n")
	}
	for _, host := range []string{"localhost", "127.0.0.1"} {
		identity := "'" + a.Username + "'@'" + host + "'"
		out.WriteString("REVOKE ALL PRIVILEGES, GRANT OPTION FROM " + identity + ";\n")
		if a.Status == "quarantined" {
			continue
		}
		for _, db := range dbs {
			out.WriteString("GRANT " + strings.Join(accountPrivileges(a.Role), ", ") + " ON `" + db.Name + "`.* TO " + identity + ";\n")
		}
	}
	return out.String(), nil
}
func setMySQLAccountLock(ctx context.Context, s core.DatabaseServer, a core.DatabaseAccount, locked bool) error {
	if !validMySQLScopedIdentity(a) || a.ServerID != s.ID {
		return errors.New("账号不属于实例")
	}
	verb := "UNLOCK"
	if locked {
		verb = "LOCK"
	}
	statement := ""
	for _, host := range []string{"localhost", "127.0.0.1"} {
		statement += "ALTER USER '" + a.Username + "'@'" + host + "' ACCOUNT " + verb + ";\n"
	}
	_, e := mysqlQuery(ctx, s, statement)
	return e
}
func killMySQLAccountConnections(ctx context.Context, s core.DatabaseServer, a core.DatabaseAccount) error {
	if !validMySQLScopedIdentity(a) || a.ServerID != s.ID {
		return errors.New("账号不属于实例")
	}
	ids, e := mysqlQuery(ctx, s, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER='"+a.Username+"' ORDER BY ID;\n")
	if e != nil {
		return e
	}
	for _, id := range strings.Fields(ids) {
		n, e := strconv.ParseUint(id, 10, 64)
		if e != nil || n == 0 {
			return errors.New("连接标识无效")
		}
		_, e = mysqlQuery(ctx, s, "KILL CONNECTION "+strconv.FormatUint(n, 10)+";\n")
		if e != nil && !strings.Contains(e.Error(), "(MySQL 1094)") {
			return e
		}
	}
	count, e := mysqlQuery(ctx, s, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER='"+a.Username+"';\n")
	if e != nil {
		return e
	}
	if count != "0" {
		return errors.New("账号仍有活动连接")
	}
	return nil
}
func verifyMySQLAccountGrants(ctx context.Context, s core.DatabaseServer, a core.DatabaseAccount, dbs []core.Database, locked bool) error {
	if e := validateAccountDatabases(a, dbs); e != nil {
		return e
	}
	if a.ServerID != s.ID {
		return errors.New("账号所属实例无效")
	}
	if a.Status == "quarantined" {
		locked = true
	}
	expectedLock := "N"
	if locked {
		expectedLock = "Y"
	}
	users, e := mysqlQuery(ctx, s, "SELECT Host,account_locked FROM mysql.user WHERE User='"+a.Username+"' ORDER BY Host;\n")
	if e != nil {
		return e
	}
	if users != "127.0.0.1\t"+expectedLock+"\nlocalhost\t"+expectedLock {
		return errors.New("账号连接来源或锁定状态不符")
	}
	for _, host := range []string{"localhost", "127.0.0.1"} {
		grantee := "CONCAT(QUOTE('" + a.Username + "'),'@',QUOTE('" + host + "'))"
		grants, e := mysqlQuery(ctx, s, "SELECT TABLE_SCHEMA,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE="+grantee+" ORDER BY TABLE_SCHEMA,PRIVILEGE_TYPE;\n")
		if e != nil {
			return e
		}
		expected := []string{}
		for _, db := range dbs {
			if a.Status == "quarantined" {
				break
			}
			for _, p := range accountPrivileges(a.Role) {
				expected = append(expected, db.Name+"\t"+p+"\tNO")
			}
		}
		sort.Strings(expected)
		actual := strings.Split(grants, "\n")
		if grants == "" {
			actual = nil
		}
		sort.Strings(actual)
		if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
			return errors.New("实际数据库权限与所选范围不一致")
		}
		global, e := mysqlQuery(ctx, s, "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE="+grantee+" AND (PRIVILEGE_TYPE<>'USAGE' OR IS_GRANTABLE<>'NO');\n")
		if e != nil {
			return e
		}
		if global != "0" {
			return errors.New("账号含有意外的全局权限")
		}
	}
	// The model grants whole schemas only. Check narrower grants too, including
	// on completed-task replay, so external table/routine grants cannot pass as readonly.
	extra, e := mysqlQuery(ctx, s, "SELECT (SELECT COUNT(*) FROM mysql.role_edges WHERE TO_USER='"+a.Username+"')+(SELECT COUNT(*) FROM mysql.proxies_priv WHERE User='"+a.Username+"')+(SELECT COUNT(*) FROM mysql.global_grants WHERE USER='"+a.Username+"')+(SELECT COUNT(*) FROM mysql.tables_priv WHERE User='"+a.Username+"')+(SELECT COUNT(*) FROM mysql.columns_priv WHERE User='"+a.Username+"')+(SELECT COUNT(*) FROM mysql.procs_priv WHERE User='"+a.Username+"');\n")
	if e != nil {
		return e
	}
	if extra != "0" {
		return errors.New("账号含有模型外的角色、代理、动态或对象级授权")
	}
	return nil
}
func readMySQLAccountCredential(server, id, username string) (mysqlCredential, error) {
	var c mysqlCredential
	if !core.ValidID(server) || !core.ValidID(id) || username != "app_"+id[:20] {
		return c, errors.New("无效账号凭据身份")
	}
	dir, e := importRoot(mysqlAccountDir(server, id))
	if e != nil {
		return c, e
	}
	defer dir.Close()
	m, e := readMySQLAccount(server, id)
	if e != nil {
		return c, e
	}
	if !validAccountCredentialRef(m.CredentialRef) {
		return c, errors.New("账号凭据引用无效")
	}
	f, e := openImportFile(dir, m.CredentialRef)
	if e != nil {
		return c, e
	}
	defer f.Close()
	e = json.NewDecoder(io.LimitReader(f, 4096)).Decode(&c)
	if e == nil && (c.Username != username || len(c.Password) != 64 || !core.ValidID(c.Password[:32]) || !core.ValidID(c.Password[32:])) {
		e = errors.New("数据库账号私有凭据无效")
	}
	return c, e
}
func prepareMySQLAccountDirectory(server, id string) error {
	if !core.ValidID(server) || !core.ValidID(id) {
		return errors.New("账号身份无效")
	}
	path := mysqlAccountDir(server, id)
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	root, e := importRoot(path)
	if root != nil {
		root.Close()
	}
	return e
}

func sameAccountSpec(a, b core.DatabaseAccount) bool {
	type spec struct {
		ID, ServerID, Name, Username, Role string
		IDs                                []string
		Enabled                            bool
		Revision                           int64
		Quarantined                        bool
	}
	canonical := func(a core.DatabaseAccount) []byte {
		ids := append([]string(nil), a.DatabaseIDs...)
		sort.Strings(ids)
		v, _ := json.Marshal(spec{a.ID, a.ServerID, a.Name, a.Username, a.Role, ids, a.Enabled, a.Revision, a.Status == "quarantined"})
		return v
	}
	return string(canonical(a)) == string(canonical(b))
}
func ownedAccountDatabases(s core.DatabaseServer, a core.DatabaseAccount) ([]core.Database, error) {
	dbs := []core.Database{}
	for _, id := range a.DatabaseIDs {
		d, e := readOwnedDatabase(s, id)
		if e != nil {
			return nil, e
		}
		dbs = append(dbs, d)
	}
	return dbs, validateAccountDatabases(a, dbs)
}
func applyMySQLAccount(ctx context.Context, s core.DatabaseServer, a core.DatabaseAccount, dbs []core.Database, cred mysqlCredential, create, verifyCredential bool) error {
	// Underscores in managed database names must remain literal in GRANT scopes.
	partial, e := mysqlQuery(ctx, s, "SELECT @@partial_revokes;\n")
	if e != nil {
		return e
	}
	if partial != "1" {
		return errors.New("实例未启用数据库授权字面范围保护")
	}
	statement, e := accountGrantSQL(a, dbs, cred, create)
	if e != nil {
		return e
	}
	if _, e = mysqlQuery(ctx, s, statement); e != nil {
		return e
	}
	if e = killMySQLAccountConnections(ctx, s, a); e != nil {
		return e
	}
	if a.Status != "quarantined" && (a.Enabled || verifyCredential) {
		// Verify a new candidate credential through a real unprivileged client before
		// publishing it. Only the freshly assigned random password can authenticate.
		if e = setMySQLAccountLock(ctx, s, a, false); e != nil {
			return e
		}
		probe := dbs[0]
		probe.Username = a.Username
		if e = importClient(ctx, s, probe, cred, strings.NewReader("SELECT DATABASE();\n"), io.Discard); e != nil {
			lockCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_ = setMySQLAccountLock(lockCtx, s, a, true)
			cancel()
			return errors.New("候选数据库账号未通过真实认证")
		}
	}
	if !a.Enabled || a.Status == "quarantined" {
		if e = setMySQLAccountLock(ctx, s, a, true); e != nil {
			return e
		}
		if e = killMySQLAccountConnections(ctx, s, a); e != nil {
			return e
		}
	}
	return verifyMySQLAccountGrants(ctx, s, a, dbs, !a.Enabled)
}
func runMySQLAccountJob(ctx context.Context, op core.DatabaseOperation, add func(string)) error {
	if op.Account == nil || !core.ValidDatabaseAccount(*op.Account) || op.Account.ServerID != op.Server.ID || !core.ValidID(op.JobID) {
		return errors.New("账号任务归属无效")
	}
	a := *op.Account
	if e := validateMySQLAccountTransition(op); e != nil {
		return e
	}
	if (op.Action == "quarantine_account") != (a.Status == "quarantined") {
		return errors.New("账号目标状态与操作不一致")
	}
	switch op.Action {
	case "create_account", "update_account", "rotate_account", "enable_account", "disable_account", "quarantine_account", "restore_account":
	default:
		return errors.New("账号操作无效")
	}
	if e := prepareMySQLAccountDirectory(op.Server.ID, a.ID); e != nil {
		return e
	}
	dir := mysqlAccountDir(op.Server.ID, a.ID)
	m, e := readMySQLAccount(op.Server.ID, a.ID)
	if e == nil {
		if m.LastJobID == op.JobID && m.Account.Status == core.DatabaseAccountFinalStatus(op.Action) && sameAccountSpec(m.Account, a) {
			dbs, er := ownedAccountDatabases(op.Server, a)
			if er != nil {
				return er
			}
			if er = verifyMySQLAccountGrants(ctx, op.Server, a, dbs, !a.Enabled); er != nil {
				return er
			}
			folder, er := os.Open(dir)
			if er != nil {
				return er
			}
			er = folder.Sync()
			folder.Close()
			if er != nil {
				return errors.New("账号清单仍无法确认持久化")
			}
			add("账号操作已完成，核对实际授权和清单持久化后保留现有凭据")
			return nil
		}
		if op.Action == "create_account" {
			if m.LastJobID != op.JobID || m.Account.Status != "creating" || !sameAccountSpec(m.Account, a) {
				return errors.New("账号身份已被其他任务使用")
			}
		} else if op.PreviousAccount == nil || !sameAccountSpec(m.Account, *op.PreviousAccount) || (m.Account.Status != "ready" && m.Account.Status != "quarantined") {
			return errors.New("账号版本或原授权已变化，拒绝覆盖")
		}
		if op.Action != "create_account" && ((op.Action == "restore_account") != (m.Account.Status == "quarantined")) {
			return errors.New("回收账号只能通过恢复任务重新交付")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else {
		if op.Action != "create_account" {
			return errors.New("账号原清单缺失，拒绝重建已有身份")
		}
		count, e := mysqlQuery(ctx, op.Server, "SELECT COUNT(*) FROM mysql.user WHERE User='"+a.Username+"';\n")
		if e != nil {
			return e
		}
		if count != "0" {
			return errors.New("MySQL 中已有未由此任务创建的同名账号")
		}
		m = mysqlAccountManifest{Account: a, LastJobID: op.JobID}
		m.Account.Status = "creating"
		if e = writeJSON(dir+"/manifest.json", m); e != nil {
			return e
		}
	}
	dbs, e := ownedAccountDatabases(op.Server, a)
	if e != nil {
		return e
	}
	if op.Action == "quarantine_account" {
		if e = requireNoMySQLAccountDefiners(ctx, op.Server, a); e != nil {
			return e
		}
	}
	var oldCredential mysqlCredential
	if op.Action != "create_account" {
		oldCredential, e = readMySQLAccountCredential(op.Server.ID, a.ID, a.Username)
		if e != nil {
			return e
		}
	}
	credential := oldCredential
	if op.Action == "create_account" || op.Action == "rotate_account" {
		credential, e = ensureCredential(dir+"/pending-"+op.JobID+".json", a.Username)
		if e != nil {
			return e
		}
	}
	rollback := func(cause error) error {
		add("提交未完成，开始恢复：" + cause.Error())
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if op.Action == "create_account" {
			_ = setMySQLAccountLock(rollbackCtx, op.Server, a, true)
			_ = killMySQLAccountConnections(rollbackCtx, op.Server, a)
			return errors.New("新账号尚未交付，已尝试锁定；请核对原任务后重试")
		}
		oldDBs, readErr := ownedAccountDatabases(op.Server, m.Account)
		if readErr != nil {
			return errors.New("账号操作失败；原授权引用无法读取，需核对原任务")
		}
		if restoreErr := applyMySQLAccount(rollbackCtx, op.Server, m.Account, oldDBs, oldCredential, false, false); restoreErr != nil {
			return errors.New("账号操作失败且原授权未完全恢复；私有凭据及任务均已保留")
		}
		add("操作未提交，已核对恢复原权限、密码和启停状态")
		return errors.New("账号操作失败，已恢复原授权、密码与启停状态")
	}
	add("核对账号、原版本和数据库范围；密码不进入任务参数与日志")
	if e = applyMySQLAccount(ctx, op.Server, a, dbs, credential, op.Action == "create_account", op.Action == "rotate_account" || op.Action == "create_account"); e != nil {
		return rollback(e)
	}
	if op.Action == "quarantine_account" {
		if e = requireNoMySQLAccountDefiners(ctx, op.Server, a); e != nil {
			return rollback(e)
		}
	}
	credentialRef := m.CredentialRef
	if op.Action == "create_account" || op.Action == "rotate_account" {
		credentialRef = "pending-" + op.JobID + ".json"
	}
	a.Status = core.DatabaseAccountFinalStatus(op.Action)
	if e = writeJSON(dir+"/manifest.json", mysqlAccountManifest{Account: a, LastJobID: op.JobID, CredentialRef: credentialRef}); e != nil {
		// A rename may have succeeded before directory fsync failed. Do not restore
		// old SQL credentials while the visible manifest already points at the new.
		current, readErr := readMySQLAccount(op.Server.ID, a.ID)
		if readErr == nil && current.LastJobID == op.JobID && current.Account.Status == a.Status && sameAccountSpec(current.Account, a) && current.CredentialRef == credentialRef {
			return errors.New("账号已应用，但清单持久化未确认；请核对原任务后重试")
		}
		if readErr != nil || !sameAccountSpec(current.Account, m.Account) || current.LastJobID != m.LastJobID {
			return errors.New("账号清单状态不明确，已保留凭据；请核对原任务")
		}
		return rollback(e)
	}
	add("实际密码认证、数据库权限、全局权限及锁定状态核对通过")
	if a.Status == "quarantined" {
		add("账号已移入回收站：直接登录已锁定、授权已撤销；身份、名称和原凭据保留，可恢复")
	} else if !a.Enabled {
		add("账号已锁定，直接连接已结束；既有 DEFINER 对象保持原语义")
	}
	return nil
}

func mysqlAccountRoutes(m *http.ServeMux) {
	mysqlAccountRecycleRoutes(m)
	m.HandleFunc("POST /v1/databases/accounts/credentials", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ServerID  string `json:"server_id"`
			AccountID string `json:"account_id"`
			Revision  int64  `json:"revision"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		manifest, e := readMySQLAccount(in.ServerID, in.AccountID)
		if e != nil {
			respond(w, 409, map[string]string{"error": "账号清单不可读取"})
			return
		}
		a := manifest.Account
		if a.Revision != in.Revision || a.Status != "ready" {
			respond(w, 409, map[string]string{"error": "账号版本不匹配或尚未交付"})
			return
		}
		server, e := readMySQL(in.ServerID)
		if e != nil {
			respond(w, 409, map[string]string{"error": "账号所属实例不可读取"})
			return
		}
		dbs, e := ownedAccountDatabases(server.Server, a)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		names := []string{}
		for _, d := range dbs {
			names = append(names, d.Name)
		}
		credential, e := readMySQLAccountCredential(a.ServerID, a.ID, a.Username)
		if e != nil {
			respond(w, 409, map[string]string{"error": "账号私有凭据不可读取"})
			return
		}
		respond(w, 200, map[string]any{"username": credential.Username, "password": credential.Password, "host": "127.0.0.1", "port": server.Server.Port, "socket": mysqlSocket(server.Server.ID), "databases": names, "enabled": a.Enabled, "revision": a.Revision})
	})
}
