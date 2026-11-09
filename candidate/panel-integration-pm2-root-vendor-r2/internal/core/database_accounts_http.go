package core

import "net/http"

func (a *Server) databaseAccountRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/databases/accounts/{id}/removal-plan", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		account, e := a.Store.DatabaseAccount(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "数据库账号不存在")
			return
		}
		if account.Status != "ready" && account.Status != "quarantined" {
			fail(w, 409, "请先完成该账号的原任务")
			return
		}
		var out DatabaseAccountRemovalPlan
		if e = a.Executor.Call(r.Context(), "POST", "/v1/databases/accounts/removal-plan", map[string]any{"server_id": account.ServerID, "account_id": account.ID, "revision": account.Revision}, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/databases/accounts/{id}/latest-job", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.DatabaseAccount(r.PathValue("id")); e != nil {
			fail(w, 404, "数据库账号不存在")
			return
		}
		var id string
		if e := a.Store.DB.QueryRow(`SELECT id FROM mysql_jobs WHERE json_extract(payload,'$.account.id')=? ORDER BY created_at DESC,rowid DESC LIMIT 1`, r.PathValue("id")).Scan(&id); e != nil {
			fail(w, 404, "账号任务不存在")
			return
		}
		send(w, 200, map[string]string{"job_id": id})
	}))

	m.HandleFunc("GET /api/databases/accounts", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		xs, e := a.Store.DatabaseAccounts()
		if e != nil {
			fail(w, 500, "读取数据库账号失败")
			return
		}
		send(w, 200, xs)
	}))
	m.HandleFunc("POST /api/databases/accounts", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ServerID    string   `json:"server_id"`
			Name        string   `json:"name"`
			Role        string   `json:"role"`
			DatabaseIDs []string `json:"database_ids"`
		}
		if !decode(w, r, &in) {
			return
		}
		server, e := a.Store.DatabaseServer(in.ServerID)
		if e != nil || server.Status != "running" {
			fail(w, 409, "请选择运行中的 MySQL 实例")
			return
		}
		a.queueDatabase(w, r, u, DatabaseOperation{Action: "create_account", Server: server, Account: &DatabaseAccount{Name: in.Name, Role: in.Role, DatabaseIDs: in.DatabaseIDs}})
	}))
	m.HandleFunc("POST /api/databases/accounts/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		account, e := a.Store.DatabaseAccount(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "数据库账号不存在")
			return
		}
		server, e := a.Store.DatabaseServer(account.ServerID)
		if e != nil {
			fail(w, 404, "账号所属实例不存在")
			return
		}
		if r.PathValue("action") == "credentials" {
			if account.Status != "ready" {
				fail(w, 409, "账号操作尚未完成，请先核对原任务")
				return
			}
			var out map[string]any
			if e = a.Executor.Call(r.Context(), "POST", "/v1/databases/accounts/credentials", map[string]any{"server_id": server.ID, "account_id": account.ID, "revision": account.Revision}, &out); e != nil {
				fail(w, 409, e.Error())
				return
			}
			_ = a.Store.Audit(u.Username, "mysql.account.credentials", account.ID, "success")
			send(w, 200, out)
			return
		}
		var in struct {
			Revision    int64    `json:"revision"`
			ConfirmName string   `json:"confirm_name"`
			Role        string   `json:"role"`
			DatabaseIDs []string `json:"database_ids"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.ConfirmName != account.Name {
			fail(w, 400, "请输入账号名称确认")
			return
		}
		if server.Status != "running" {
			fail(w, 409, "实例未运行，无法更改账号")
			return
		}
		action := ""
		switch r.PathValue("action") {
		case "permissions":
			action = "update_account"
			account.Role = in.Role
			account.DatabaseIDs = in.DatabaseIDs
		case "rotate-password":
			action = "rotate_account"
		case "enable":
			action = "enable_account"
		case "disable":
			action = "disable_account"
		case "quarantine":
			action = "quarantine_account"
		case "restore":
			action = "restore_account"
		default:
			fail(w, 404, "账号操作不存在")
			return
		}
		if (action == "quarantine_account" && account.Status == "ready") || (action == "restore_account" && account.Status == "quarantined") {
			var plan DatabaseAccountRemovalPlan
			if e = a.Executor.Call(r.Context(), "POST", "/v1/databases/accounts/removal-plan", map[string]any{"server_id": account.ServerID, "account_id": account.ID, "revision": account.Revision}, &plan); e != nil {
				fail(w, 409, e.Error())
				return
			}
			if len(plan.BlockedReasons) > 0 {
				fail(w, 409, plan.BlockedReasons[0])
				return
			}
		}
		account.Revision = in.Revision
		a.queueDatabase(w, r, u, DatabaseOperation{Action: action, Server: server, Account: &account})
	}))
}
