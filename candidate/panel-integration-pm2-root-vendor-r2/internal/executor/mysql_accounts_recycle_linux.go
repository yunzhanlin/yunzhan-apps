//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"strconv"
	"strings"
)

func validateMySQLAccountTransition(op core.DatabaseOperation) error {
	if op.Account == nil || !core.ValidDatabaseAccount(*op.Account) {
		return errors.New("账号身份无效")
	}
	a := *op.Account
	if op.Action == "create_account" {
		if op.PreviousAccount != nil || a.Revision != 1 || !a.Enabled || a.Status != "creating" {
			return errors.New("新账号初始状态无效")
		}
		return nil
	}
	if op.PreviousAccount == nil || !core.ValidDatabaseAccount(*op.PreviousAccount) {
		return errors.New("账号原状态无效")
	}
	old := *op.PreviousAccount
	expectedStatus := "ready"
	if op.Action == "restore_account" {
		expectedStatus = "quarantined"
	}
	if old.Status != expectedStatus {
		return errors.New("账号原状态与操作不匹配")
	}
	expected := old
	expected.Revision++
	expected.Status = a.Status
	switch op.Action {
	case "update_account":
		expected.Role = a.Role
		expected.DatabaseIDs = a.DatabaseIDs
	case "enable_account":
		expected.Enabled = true
	case "disable_account":
		expected.Enabled = false
	case "rotate_account", "quarantine_account", "restore_account":
	default:
		return errors.New("账号操作无效")
	}
	if !sameAccountSpec(expected, a) {
		return errors.New("账号任务更改了操作范围外的身份、权限或修订")
	}
	return nil
}

func mysqlAccountDefiners(ctx context.Context, s core.DatabaseServer, a core.DatabaseAccount) ([]core.DatabaseAccountReference, error) {
	if !validMySQLScopedIdentity(a) || a.ServerID != s.ID {
		return nil, errors.New("账号归属无效")
	}
	refs := []core.DatabaseAccountReference{}
	for _, q := range []struct{ kind, table, schema, name string }{
		{"view", "VIEWS", "TABLE_SCHEMA", "TABLE_NAME"},
		{"routine", "ROUTINES", "ROUTINE_SCHEMA", "ROUTINE_NAME"},
		{"trigger", "TRIGGERS", "TRIGGER_SCHEMA", "TRIGGER_NAME"},
		{"event", "EVENTS", "EVENT_SCHEMA", "EVENT_NAME"},
	} {
		// JSON encodes quoted identifiers/newlines without ambiguous tab parsing.
		raw, e := mysqlQuery(ctx, s, "SELECT JSON_ARRAY("+q.schema+","+q.name+") FROM information_schema."+q.table+" WHERE DEFINER IN ('"+a.Username+"@localhost','"+a.Username+"@127.0.0.1') ORDER BY "+q.schema+","+q.name+" LIMIT 50;\n")
		if e != nil {
			return nil, e
		}
		if raw == "" {
			continue
		}
		for _, line := range strings.Split(raw, "\n") {
			var v []string
			if e = json.Unmarshal([]byte(line), &v); e != nil || len(v) != 2 {
				return nil, errors.New("定义者引用查询结果无效")
			}
			refs = append(refs, core.DatabaseAccountReference{Kind: q.kind, Database: v[0], Name: v[1]})
		}
	}
	return refs, nil
}
func requireNoMySQLAccountDefiners(ctx context.Context, s core.DatabaseServer, a core.DatabaseAccount) error {
	refs, e := mysqlAccountDefiners(ctx, s, a)
	if e != nil {
		return e
	}
	if len(refs) > 0 {
		return errors.New("账号仍被视图、存储程序、触发器或事件引用；请先处理定义者依赖")
	}
	return nil
}
func mysqlAccountRecycleRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/databases/accounts/removal-plan", func(w http.ResponseWriter, r *http.Request) {
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
		if a.Revision != in.Revision || (a.Status != "ready" && a.Status != "quarantined") {
			respond(w, 409, map[string]string{"error": "账号版本变化或原任务尚未完成"})
			return
		}
		s, e := readMySQL(in.ServerID)
		if e != nil {
			respond(w, 409, map[string]string{"error": "账号所属实例不可读取"})
			return
		}
		plan := core.DatabaseAccountRemovalPlan{AccountID: a.ID, Revision: a.Revision, Status: a.Status, References: []core.DatabaseAccountReference{}, BlockedReasons: []string{}}
		dbs, e := ownedAccountDatabases(s.Server, a)
		for _, db := range dbs {
			if db.Status == "quarantined" {
				plan.BlockedReasons = append(plan.BlockedReasons, "请先恢复账号引用的数据库，再恢复账号")
				break
			}
		}
		if e == nil {
			e = verifyMySQLAccountGrants(r.Context(), s.Server, a, dbs, !a.Enabled)
		}
		if e != nil {
			plan.BlockedReasons = append(plan.BlockedReasons, e.Error())
		}
		refs, e := mysqlAccountDefiners(r.Context(), s.Server, a)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		plan.References = refs
		if a.Status == "ready" && len(refs) > 0 {
			plan.BlockedReasons = append(plan.BlockedReasons, "仍有以该账号为定义者的对象，请先处理引用；每类最多显示 50 项")
		}
		connections, e := mysqlQuery(r.Context(), s.Server, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER='"+a.Username+"';\n")
		if e == nil {
			plan.Connections, e = strconv.Atoi(connections)
		}
		if e != nil {
			respond(w, 409, map[string]string{"error": "账号连接数不可核对"})
			return
		}
		respond(w, 200, plan)
	})
}
