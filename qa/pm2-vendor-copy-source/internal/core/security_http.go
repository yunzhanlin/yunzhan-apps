package core

import (
	"net"
	"net/http"
	"strings"
	"time"
)

func requestConnectionID(r *http.Request) string {
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		if value := strings.TrimSpace(r.Header.Get("X-Panel-Connection")); value != "" && len(value) <= 80 {
			return "proxy:" + value
		}
	}
	host, port, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return "direct:" + host + ":" + port
	}
	return "direct:" + r.RemoteAddr
}

func (a *Server) securityRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/security/firewall", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		a.Store.PruneExpiredFirewallPending()
		config, e := a.Store.Firewall()
		if e != nil {
			fail(w, 500, "读取防火墙设置失败")
			return
		}
		var status FirewallStatus
		if e = a.Executor.Call(r.Context(), http.MethodGet, "/v1/security/firewall", nil, &status); e != nil {
			fail(w, 503, e.Error())
			return
		}
		if id, _, deadline, pendingErr := a.Store.FirewallPending(); pendingErr == nil {
			if status.Pending && status.ChangeID == id {
				status.Deadline = deadline
			} else {
				a.Store.ClearFirewallPending(id)
				status.Pending = false
				status.ChangeID = ""
			}
		}
		send(w, 200, FirewallPage{Config: config, Status: status})
	}))
	m.HandleFunc("POST /api/security/firewall/preview", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in FirewallConfig
		if !decode(w, r, &in) {
			return
		}
		v, e := a.Store.ValidateFirewall(in)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		v.Revision++
		var result FirewallApplyResult
		if e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/security/firewall/preview", FirewallApplyRequest{Config: v}, &result); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, result)
	}))
	m.HandleFunc("PUT /api/security/firewall", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in FirewallConfig
		if !decode(w, r, &in) {
			return
		}
		v, e := a.Store.ValidateFirewall(in)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		current, e := a.Store.Firewall()
		if e != nil || current.Revision != v.Revision {
			fail(w, 409, "防火墙配置已变化，请刷新后重试")
			return
		}
		if id, _, expires, pe := a.Store.FirewallPending(); pe == nil && expires >= time.Now().Unix() {
			fail(w, 409, "已有防火墙变更等待确认："+id)
			return
		}
		changeID := ID()
		v.Revision++
		var result FirewallApplyResult
		if e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/security/firewall/apply", FirewallApplyRequest{Config: v, ChangeID: changeID}, &result); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if e = a.Store.BeginFirewallChange(in, changeID, requestConnectionID(r), u.Username, result.Deadline); e != nil {
			var ignored map[string]any
			_ = a.Executor.Call(r.Context(), http.MethodPost, "/v1/security/firewall/rollback", FirewallConfirmRequest{ChangeID: changeID}, &ignored)
			fail(w, 409, e.Error())
			return
		}
		w.Header().Set("Connection", "close")
		r.Close = true
		send(w, 202, result)
	}))
	m.HandleFunc("POST /api/security/firewall/confirm", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in FirewallConfirmRequest
		if !decode(w, r, &in) {
			return
		}
		id, originalConnection, expires, e := a.Store.FirewallPending()
		if e != nil || id != in.ChangeID {
			fail(w, 409, "防火墙变更不存在或已经恢复")
			return
		}
		connection := requestConnectionID(r)
		if expires < time.Now().Unix() {
			fail(w, 409, "确认期限已过，防火墙将自动恢复")
			return
		}
		if connection == originalConnection {
			fail(w, 409, "请从新的管理连接确认防火墙")
			return
		}
		var ignored map[string]any
		if e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/security/firewall/confirm", in, &ignored); e != nil {
			fail(w, 409, e.Error())
			return
		}
		updated, e := a.Store.ConfirmFirewall(in.ChangeID, connection, u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, updated)
	}))
	m.HandleFunc("GET /api/security/ssh", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var status SSHStatus
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/security/ssh", nil, &status); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, status)
	}))
}
