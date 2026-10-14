package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type platformMaintenanceGrant struct {
	ID, Owner string
	Commands  []string
	Expires   int64
	Revoked   bool
}

func (s *Store) migratePlatformMaintenance() error {
	_, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS platform_maintenance_grants(token_hash TEXT PRIMARY KEY,owner_id TEXT NOT NULL,commands TEXT NOT NULL,expires_at INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS platform_maintenance_operations(request_id TEXT PRIMARY KEY,grant_id TEXT NOT NULL,actor_id TEXT NOT NULL,request TEXT NOT NULL,request_sha TEXT NOT NULL,state TEXT NOT NULL,record TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);`)
	return err
}
func platformMaintenanceAdmin(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, owner string) error {
	a, err := readUserAccessContext(ctx, db, owner)
	if err != nil || a.Role != "admin" || !containsMenu(a.MenuIDs, "system-tools") {
		return errors.New("需要当前管理员的系统工具授权")
	}
	return nil
}
func platformMaintenanceCommandAllowed(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, owner, command string) error {
	if err := platformMaintenanceAdmin(ctx, db, owner); err != nil {
		return err
	}
	if command == "nginx-reload" {
		access, err := readUserAccessContext(ctx, db, owner)
		if err != nil || !fullAdministrator(access) {
			return errors.New("主机级重载只允许当前完整权限管理员")
		}
	}
	return nil
}
func (s *Store) issuePlatformMaintenanceGrant(ctx context.Context, actor string, in PlatformMaintenanceGrantInput) (any, error) {
	raw, _ := json.Marshal(in)
	if _, err := DecodePlatformMaintenanceGrant(raw); err != nil {
		return nil, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = platformMaintenanceAdmin(ctx, tx, actor); err != nil {
		return nil, err
	}
	for _, command := range in.Commands {
		if err = platformMaintenanceCommandAllowed(ctx, tx, actor, command); err != nil {
			return nil, err
		}
	}
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM platform_maintenance_grants").Scan(&count) != nil || count >= PlatformMaintenanceGrantLimit {
		return nil, errors.New("维护授权达到128份保留上限，未自动删除或恢复旧秘密")
	}
	token := Token()
	id := Hash(token)
	issuedAt := time.Now().UTC()
	expires := issuedAt.Unix() + int64(in.Minutes)*60
	commands, _ := json.Marshal(in.Commands)
	if _, err = tx.ExecContext(ctx, "INSERT INTO platform_maintenance_grants(token_hash,owner_id,commands,expires_at,created_at) VALUES(?,?,?,?,?)", id, actor, string(commands), expires, issuedAt.Format(time.RFC3339)); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'platform.maintenance.grant.issue',?,'issued',?)", actor, id, Now()); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]any{"token": token, "grant_id": id, "commands": in.Commands, "expires_at": expires, "scope": "nginx-maintenance", "one_time_secret": true}, nil
}
func validPlatformMaintenanceLifetime(created string, expires int64) bool {
	issued, err := time.Parse(time.RFC3339, created)
	if err != nil || issued.UTC().Format(time.RFC3339) != created || issued.Unix() > time.Now().Unix()+120 {
		return false
	}
	return expires >= issued.Unix()+300 && expires <= issued.Unix()+86400
}
func (s *Store) platformMaintenanceGrant(ctx context.Context, id string) (platformMaintenanceGrant, error) {
	var out platformMaintenanceGrant
	var commands, created string
	var revoked int
	if !platformMaintenanceSHA.MatchString(id) || s.DB.QueryRowContext(ctx, "SELECT token_hash,owner_id,commands,expires_at,revoked,created_at FROM platform_maintenance_grants WHERE token_hash=?", id).Scan(&out.ID, &out.Owner, &commands, &out.Expires, &revoked, &created) != nil || json.Unmarshal([]byte(commands), &out.Commands) != nil || !validatePlatformMaintenanceCommands(out.Commands) || !ValidID(out.Owner) || revoked < 0 || revoked > 1 || !validPlatformMaintenanceLifetime(created, out.Expires) {
		return out, errors.New("维护授权身份或字段不可核对")
	}
	out.Revoked = revoked == 1
	return out, nil
}
func (a *Server) platformMaintenanceInstalled(ctx context.Context) error {
	var m struct {
		Status SoftwareAppStatus `json:"status"`
	}
	if a.Executor.Call(ctx, "GET", "/v1/app-modules/platform-ops", nil, &m) != nil || !knownInstalledAppModule("platform-ops", m.Status) {
		return errors.New("平台运维应用身份未核对，未执行维护")
	}
	return nil
}
func (a *Server) platformMaintenanceBearer(r *http.Request) (platformMaintenanceGrant, error) {
	var out platformMaintenanceGrant
	auth := r.Header.Get("Authorization")
	if r.Header.Get("Cookie") != "" || !strings.HasPrefix(auth, "Bearer ") || !platformMaintenanceSHA.MatchString(strings.TrimPrefix(auth, "Bearer ")) {
		return out, errors.New("仅接受独立维护令牌，不接受会话或只读摘要")
	}
	var err error
	out, err = a.Store.platformMaintenanceGrant(r.Context(), Hash(strings.TrimPrefix(auth, "Bearer ")))
	if err != nil || out.Revoked || out.Expires <= time.Now().Unix() || platformMaintenanceAdmin(r.Context(), a.Store.DB, out.Owner) != nil {
		return out, errors.New("维护授权不存在、已过期、撤销或主体权限已变化")
	}
	return out, nil
}
func (s *Store) beginPlatformMaintenance(ctx context.Context, g platformMaintenanceGrant, in PlatformMaintenanceInput) (PlatformMaintenanceNativeRequest, string, []byte, error) {
	req := PlatformMaintenanceNativeRequest{Format: 1, GrantID: g.ID, ActorID: g.Owner, Input: in}
	wire, _ := json.Marshal(req)
	pin := PlatformMaintenanceRequestSHA(req)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return req, "", nil, err
	}
	defer tx.Rollback()
	if err = platformMaintenanceAdmin(ctx, tx, g.Owner); err != nil {
		return req, "", nil, err
	}
	var commands, created string
	var expiry int64
	var revoked int
	if tx.QueryRowContext(ctx, "SELECT commands,expires_at,revoked,created_at FROM platform_maintenance_grants WHERE token_hash=? AND owner_id=?", g.ID, g.Owner).Scan(&commands, &expiry, &revoked, &created) != nil || expiry <= time.Now().Unix() || revoked != 0 || !validPlatformMaintenanceLifetime(created, expiry) {
		return req, "", nil, errors.New("派发前维护授权已失效")
	}
	var allowed []string
	if json.Unmarshal([]byte(commands), &allowed) != nil || !validatePlatformMaintenanceCommands(allowed) || !containsString(allowed, in.Command) {
		return req, "", nil, errors.New("命令超出维护授权")
	}
	if err = platformMaintenanceCommandAllowed(ctx, tx, g.Owner, in.Command); err != nil {
		return req, "", nil, err
	}
	var oldGrant, oldSHA, state, record string
	err = tx.QueryRowContext(ctx, "SELECT grant_id,request_sha,state,record FROM platform_maintenance_operations WHERE request_id=?", in.RequestID).Scan(&oldGrant, &oldSHA, &state, &record)
	if err == nil {
		if oldGrant != g.ID || oldSHA != pin {
			return req, "", nil, errors.New("原操作ID已绑定不同主体或命令，未覆盖")
		}
		return req, state, []byte(record), tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return req, "", nil, err
	}
	if in.Command == "nginx-reload" {
		var active int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM platform_maintenance_operations WHERE state IN ('dispatched','needs_attention') AND json_extract(request,'$.input.command')='nginx-reload'").Scan(&active) != nil || active != 0 {
			return req, "", nil, errors.New("本机有未核对重载，禁止换ID或授权再次派发")
		}
	}
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM platform_maintenance_operations").Scan(&count) != nil || count >= PlatformMaintenanceOperationLimit {
		return req, "", nil, errors.New("维护原操作已达1024份保留上限，不自动删除")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO platform_maintenance_operations(request_id,grant_id,actor_id,request,request_sha,state,created_at,updated_at) VALUES(?,?,?,?,?,'dispatched',?,?)", in.RequestID, g.ID, g.Owner, string(wire), pin, Now(), Now()); err != nil {
		return req, "", nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'platform.maintenance.command.request',?,?,?)", g.Owner, in.RequestID, pin, Now()); err != nil {
		return req, "", nil, err
	}
	return req, "new", nil, tx.Commit()
}
func (s *Store) finishPlatformMaintenance(ctx context.Context, req PlatformMaintenanceNativeRequest, record []byte) error {
	out, err := DecodePlatformMaintenanceRecord(record, req)
	if err != nil || out.State == "started" {
		return errors.New("原生回执未完成，保留待核对")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var original, state string
	if tx.QueryRowContext(ctx, "SELECT request_sha,state FROM platform_maintenance_operations WHERE request_id=? AND grant_id=?", req.Input.RequestID, req.GrantID).Scan(&original, &state) != nil || original != out.RequestSHA {
		return errors.New("原派发身份已变化")
	}
	if state == "completed" || state == "failed" {
		var old string
		if tx.QueryRowContext(ctx, "SELECT record FROM platform_maintenance_operations WHERE request_id=?", req.Input.RequestID).Scan(&old) != nil || old != string(record) {
			return errors.New("原终态不可覆盖")
		}
		return tx.Commit()
	}
	if state != "dispatched" && state != "needs_attention" {
		return errors.New("原派发状态无效")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE platform_maintenance_operations SET state=?,record=?,updated_at=? WHERE request_id=?", out.State, string(record), Now(), req.Input.RequestID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'platform.maintenance.command.complete',?,?,?)", req.ActorID, req.Input.RequestID, out.Outcome, Now()); err != nil {
		return err
	}
	return tx.Commit()
}
func (a *Server) platformMaintenanceRoutes(m *http.ServeMux) {
	admin := func(w http.ResponseWriter, r *http.Request, u identity) bool {
		if platformMaintenanceAdmin(r.Context(), a.Store.DB, u.ID) != nil {
			fail(w, 403, "需要维护管理员系统工具授权")
			return false
		}
		return true
	}
	base := "/api/app-modules/platform-ops/maintenance"
	m.HandleFunc("GET "+base+"/operations", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(w, r, u) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "维护库存不接受查询字段")
			return
		}
		rows, e := a.Store.DB.QueryContext(r.Context(), "SELECT request,request_sha,state,record FROM platform_maintenance_operations ORDER BY created_at,request_id LIMIT 1025")
		if e != nil {
			fail(w, 503, "原操作库存不可读")
			return
		}
		defer rows.Close()
		entries := []map[string]any{}
		for rows.Next() {
			var wire, pin, state, record string
			if rows.Scan(&wire, &pin, &state, &record) != nil {
				fail(w, 503, "原操作库存不完整")
				return
			}
			req, e := DecodePlatformMaintenanceNativeRequest([]byte(wire))
			if e != nil || PlatformMaintenanceRequestSHA(req) != pin || state != "dispatched" && state != "needs_attention" && state != "completed" && state != "failed" {
				fail(w, 503, "原操作身份或状态损坏，未提供部分清单")
				return
			}
			outcome := "unknown"
			if state == "completed" || state == "failed" {
				out, e := DecodePlatformMaintenanceRecord([]byte(record), req)
				if e != nil || out.State != state {
					fail(w, 503, "原终态回执不一致")
					return
				}
				outcome = out.Outcome
			}
			entries = append(entries, map[string]any{"request_id": req.Input.RequestID, "grant_id": req.GrantID, "command": req.Input.Command, "state": state, "outcome": outcome, "request_sha256": pin, "retry_allowed": false})
		}
		if rows.Err() != nil || len(entries) > PlatformMaintenanceOperationLimit {
			fail(w, 503, "原操作库存超过完整预算")
			return
		}
		send(w, 200, map[string]any{"entries": entries, "limit": PlatformMaintenanceOperationLimit, "read_only": true})
	}))
	m.HandleFunc("POST "+base+"/operations/{id}/reconcile", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(w, r, u) {
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 128))
		id := r.PathValue("id")
		if e != nil || string(raw) != "{}" || !ValidID(id) || r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "核对原操作标识无效")
			return
		}
		var wire, pin string
		if a.Store.DB.QueryRowContext(r.Context(), "SELECT request,request_sha FROM platform_maintenance_operations WHERE request_id=?", id).Scan(&wire, &pin) != nil {
			fail(w, 404, "原操作不存在")
			return
		}
		req, e := DecodePlatformMaintenanceNativeRequest([]byte(wire))
		if e != nil || req.Input.RequestID != id || PlatformMaintenanceRequestSHA(req) != pin {
			fail(w, 503, "原操作主体不可核对")
			return
		}
		var result json.RawMessage
		if a.Executor.Call(r.Context(), "GET", "/v1/platform-maintenance/commands/"+id, nil, &result) != nil || a.Store.finishPlatformMaintenance(r.Context(), req, result) != nil {
			send(w, 202, map[string]any{"request_id": id, "state": "needs_attention", "retry_allowed": false})
			return
		}
		send(w, 200, result)
	}))
	m.HandleFunc("GET "+base+"/grants", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(w, r, u) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "授权清单不接受查询字段")
			return
		}
		rows, err := a.Store.DB.QueryContext(r.Context(), "SELECT token_hash FROM platform_maintenance_grants ORDER BY token_hash LIMIT 129")
		if err != nil {
			fail(w, 503, "授权清单不可读取")
			return
		}
		var ids []string
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				fail(w, 503, "授权清单不完整")
				return
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(ids) > 128 {
			fail(w, 503, "授权清单超过完整预算")
			return
		}
		entries := []map[string]any{}
		for _, id := range ids {
			g, e := a.Store.platformMaintenanceGrant(r.Context(), id)
			if e != nil {
				fail(w, 503, "原授权损坏，未提供部分清单")
				return
			}
			entries = append(entries, map[string]any{"grant_id": g.ID, "commands": g.Commands, "expires_at": g.Expires, "revoked": g.Revoked, "owner_id": g.Owner})
		}
		send(w, 200, map[string]any{"entries": entries, "limit": 128, "read_only": true})
	}))
	m.HandleFunc("POST "+base+"/grants", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(w, r, u) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "授权不接受查询字段")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		in, de := DecodePlatformMaintenanceGrant(raw)
		if e != nil || de != nil {
			fail(w, 400, "维护授权字段或确认无效")
			return
		}
		if a.platformMaintenanceInstalled(r.Context()) != nil {
			fail(w, 409, "维护应用未核对，不自动安装")
			return
		}
		out, e := a.Store.issuePlatformMaintenanceGrant(r.Context(), u.ID, in)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 201, out)
	}))
	m.HandleFunc("POST "+base+"/grants/{id}/revoke", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(w, r, u) {
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 128))
		if e != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || string(raw) != "{}" || !platformMaintenanceSHA.MatchString(r.PathValue("id")) {
			fail(w, 400, "原授权撤销绑定无效")
			return
		}
		tx, e := a.Store.DB.BeginTx(r.Context(), nil)
		if e != nil {
			fail(w, 503, "撤销事务未开始")
			return
		}
		defer tx.Rollback()
		if platformMaintenanceAdmin(r.Context(), tx, u.ID) != nil {
			fail(w, 403, "撤销权限已变化")
			return
		}
		result, e := tx.ExecContext(r.Context(), "UPDATE platform_maintenance_grants SET revoked=1 WHERE token_hash=?", r.PathValue("id"))
		if e != nil {
			fail(w, 503, "未撤销原授权")
			return
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			fail(w, 409, "原维护授权不存在")
			return
		}
		if _, e = tx.ExecContext(r.Context(), "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'platform.maintenance.grant.revoke',?,'revoked',?)", u.ID, r.PathValue("id"), Now()); e != nil || tx.Commit() != nil {
			fail(w, 503, "撤销与审计未共同提交")
			return
		}
		send(w, 200, map[string]any{"grant_id": r.PathValue("id"), "revoked": true})
	}))
	m.HandleFunc("GET /api/platform-maintenance/plan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		g, e := a.platformMaintenanceBearer(r)
		if e != nil {
			fail(w, 401, "独立维护授权无效，未使用只读授权")
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "计划不接受查询字段")
			return
		}
		if a.platformMaintenanceInstalled(r.Context()) != nil {
			fail(w, 409, "维护应用身份未核对")
			return
		}
		var raw json.RawMessage
		if a.Executor.Call(r.Context(), "GET", "/v1/platform-maintenance/plan", nil, &raw) != nil {
			fail(w, 503, "完整原生维护计划不可读取")
			return
		}
		plan, e := DecodePlatformMaintenancePlan(raw)
		if e != nil {
			fail(w, 503, "原生维护计划格式无效")
			return
		}
		send(w, 200, map[string]any{"plan": plan, "grant_id": g.ID, "actor_id": g.Owner, "allowed_commands": g.Commands, "expires_at": g.Expires})
	})
	m.HandleFunc("POST /api/platform-maintenance/commands", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		g, e := a.platformMaintenanceBearer(r)
		if e != nil {
			fail(w, 401, "独立维护授权无效")
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "命令不接受查询字段")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		in, de := DecodePlatformMaintenanceInput(raw)
		if e != nil || de != nil {
			fail(w, 400, "原命令绑定无效")
			return
		}
		if a.platformMaintenanceInstalled(r.Context()) != nil {
			fail(w, 409, "维护应用未核对")
			return
		}
		req, state, record, e := a.Store.beginPlatformMaintenance(r.Context(), g, in)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		if state != "new" {
			if state == "completed" || state == "failed" {
				if _, e = DecodePlatformMaintenanceRecord(record, req); e != nil {
					fail(w, 503, "原终态回执损坏，未重发")
					return
				}
				send(w, 200, json.RawMessage(record))
				return
			}
			send(w, 202, map[string]any{"request_id": in.RequestID, "state": "needs_attention", "retry_allowed": false})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var reply json.RawMessage
		e = a.Executor.Call(ctx, "POST", "/v1/platform-maintenance/commands", req, &reply)
		if e == nil {
			e = a.Store.finishPlatformMaintenance(ctx, req, reply)
		}
		if e != nil {
			_, _ = a.Store.DB.Exec("UPDATE platform_maintenance_operations SET state='needs_attention',updated_at=? WHERE request_id=? AND state='dispatched'", Now(), in.RequestID)
			send(w, 202, map[string]any{"request_id": in.RequestID, "state": "needs_attention", "retry_allowed": false})
			return
		}
		send(w, 200, reply)
	})
	m.HandleFunc("GET /api/platform-maintenance/commands/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		g, e := a.platformMaintenanceBearer(r)
		if e != nil {
			fail(w, 401, "独立维护授权无效")
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "原任务标识无效")
			return
		}
		var wire, pin, state, record string
		if a.Store.DB.QueryRowContext(r.Context(), "SELECT request,request_sha,state,record FROM platform_maintenance_operations WHERE request_id=? AND grant_id=?", id, g.ID).Scan(&wire, &pin, &state, &record) != nil {
			fail(w, 404, "原维护任务不存在")
			return
		}
		req, e := DecodePlatformMaintenanceNativeRequest([]byte(wire))
		if e != nil || PlatformMaintenanceRequestSHA(req) != pin || req.GrantID != g.ID || req.Input.RequestID != id {
			fail(w, 503, "原维护任务绑定损坏")
			return
		}
		if state == "completed" || state == "failed" {
			if _, e = DecodePlatformMaintenanceRecord([]byte(record), req); e != nil {
				fail(w, 503, "原维护终态回执不可核对")
				return
			}
			send(w, 200, json.RawMessage(record))
			return
		}
		var reply json.RawMessage
		if a.Executor.Call(r.Context(), "GET", "/v1/platform-maintenance/commands/"+id, nil, &reply) == nil && a.Store.finishPlatformMaintenance(r.Context(), req, reply) == nil {
			send(w, 200, reply)
			return
		}
		send(w, 202, map[string]any{"request_id": id, "state": "needs_attention", "retry_allowed": false})
	})
}
