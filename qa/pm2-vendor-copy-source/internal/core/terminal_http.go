package core

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	terminalGrantLifetime     = 10 * time.Minute
	terminalRootGrantLifetime = 2 * time.Minute
)

type terminalGrant struct {
	UserID   string
	Username string
	Expires  time.Time
	Elevated bool
}

type terminalSessionOwner struct {
	UserID    string
	Elevated  bool
	TokenHash string
}

type terminalSnapshot struct {
	ID        string `json:"id"`
	Output    string `json:"output"`
	Base      uint64 `json:"base"`
	Next      uint64 `json:"next"`
	Truncated bool   `json:"truncated"`
	Running   bool   `json:"running"`
	ExitCode  int    `json:"exit_code"`
	StartedAt string `json:"started_at"`
	IdleSecs  int64  `json:"idle_seconds"`
	User      string `json:"user"`
}

func (a *Server) issueTerminalGrant(u identity, elevated bool) (string, int64) {
	raw := Token()
	lifetime := terminalGrantLifetime
	if elevated {
		lifetime = terminalRootGrantLifetime
	}
	expires := time.Now().Add(lifetime)
	a.terminalMu.Lock()
	defer a.terminalMu.Unlock()
	for key, grant := range a.terminalGrants {
		if grant.Expires.Before(time.Now()) || (grant.UserID == u.ID && grant.Elevated == elevated) {
			delete(a.terminalGrants, key)
		}
	}
	a.terminalGrants[Hash(raw)] = terminalGrant{UserID: u.ID, Username: u.Username, Expires: expires, Elevated: elevated}
	return raw, expires.Unix()
}

func (a *Server) terminalAuthorized(r *http.Request, u identity, elevated bool) bool {
	raw := strings.TrimSpace(r.Header.Get("X-Terminal-Token"))
	if len(raw) < 32 || len(raw) > 256 {
		return false
	}
	now := time.Now()
	a.terminalMu.Lock()
	defer a.terminalMu.Unlock()
	for key, grant := range a.terminalGrants {
		if grant.Expires.Before(now) {
			delete(a.terminalGrants, key)
		}
	}
	grant, ok := a.terminalGrants[Hash(raw)]
	return ok && grant.UserID == u.ID && grant.Expires.After(now) && grant.Elevated == elevated
}

func (a *Server) terminalOwned(id string, u identity, elevated bool) bool {
	a.terminalMu.Lock()
	defer a.terminalMu.Unlock()
	owner, ok := a.terminalSessions[id]
	return ok && owner.UserID == u.ID && owner.Elevated == elevated
}

func (a *Server) terminalSessionAuthorized(r *http.Request, u identity, elevated bool) bool {
	id := r.PathValue("id")
	raw := strings.TrimSpace(r.Header.Get("X-Terminal-Token"))
	if !ValidID(id) || len(raw) < 32 || len(raw) > 256 {
		return false
	}
	a.terminalMu.Lock()
	defer a.terminalMu.Unlock()
	owner, ok := a.terminalSessions[id]
	return ok && owner.UserID == u.ID && owner.Elevated == elevated && owner.TokenHash == Hash(raw)
}

func (a *Server) terminalRoutes(m *http.ServeMux) {
	type grantInput struct {
		Password     string `json:"password"`
		Code         string `json:"code"`
		Confirmation string `json:"confirmation,omitempty"`
	}
	m.HandleFunc("POST /api/terminal/grant", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !a.allowedScope(r, "terminal-grant") {
			fail(w, 429, "终端授权请求过于频繁，请稍后再试")
			return
		}
		var in grantInput
		if !decode(w, r, &in) {
			return
		}
		if e := a.Store.VerifyAccountProof(u.Username, in.Password, in.Code, a.accountSecretKey, time.Now()); e != nil {
			_ = a.Store.Audit(u.Username, "terminal.authorize", "restricted", "failed")
			fail(w, 403, "终端授权验证失败")
			return
		}
		token, expires := a.issueTerminalGrant(u, false)
		_ = a.Store.Audit(u.Username, "terminal.authorize", "restricted", "success")
		send(w, 200, map[string]any{"token": token, "expires_at": expires, "user": "panel-task", "elevated": false})
	}))
	m.HandleFunc("POST /api/terminal/elevated-grant", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !a.allowedScope(r, "terminal-root-grant") {
			fail(w, 429, "Root 终端授权请求过于频繁，请稍后再试")
			return
		}
		var in grantInput
		if !decode(w, r, &in) {
			return
		}
		if in.Confirmation != "ROOT" {
			_ = a.Store.Audit(u.Username, "terminal.root.authorize", "root", "failed")
			fail(w, 403, "请输入 ROOT 确认提权终端")
			return
		}
		if e := a.Store.VerifyAccountProof(u.Username, in.Password, in.Code, a.accountSecretKey, time.Now()); e != nil {
			_ = a.Store.Audit(u.Username, "terminal.root.authorize", "root", "failed")
			fail(w, 403, "Root 终端授权验证失败")
			return
		}
		token, expires := a.issueTerminalGrant(u, true)
		_ = a.Store.Audit(u.Username, "terminal.root.authorize", "root", "success")
		send(w, 200, map[string]any{"token": token, "expires_at": expires, "user": "root", "elevated": true})
	}))

	require := func(elevated, allowExistingSession bool, next func(http.ResponseWriter, *http.Request, identity)) http.HandlerFunc {
		return a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			if !a.terminalAuthorized(r, u, elevated) && (!allowExistingSession || !a.terminalSessionAuthorized(r, u, elevated)) {
				fail(w, 403, "终端独立授权已失效或权限类型不匹配，请重新验证管理员身份")
				return
			}
			next(w, r, u)
		})
	}

	register := func(apiPrefix, executorPrefix string, elevated bool, userLabel string) {
		auditPrefix := "terminal"
		if elevated {
			auditPrefix = "terminal.root"
		}
		m.HandleFunc("POST "+apiPrefix+"/sessions", require(elevated, false, func(w http.ResponseWriter, r *http.Request, u identity) {
			var in struct {
				Cols uint16 `json:"cols"`
				Rows uint16 `json:"rows"`
			}
			if !decode(w, r, &in) {
				return
			}
			var out terminalSnapshot
			if e := a.Executor.Call(r.Context(), http.MethodPost, executorPrefix+"/sessions", in, &out); e != nil {
				_ = a.Store.Audit(u.Username, auditPrefix+".open", userLabel, "failed")
				fail(w, 409, e.Error())
				return
			}
			a.terminalMu.Lock()
			a.terminalSessions[out.ID] = terminalSessionOwner{UserID: u.ID, Elevated: elevated, TokenHash: Hash(r.Header.Get("X-Terminal-Token"))}
			a.terminalMu.Unlock()
			_ = a.Store.Audit(u.Username, auditPrefix+".open", out.ID+":"+userLabel, "success")
			send(w, 201, out)
		}))

		m.HandleFunc("GET "+apiPrefix+"/sessions/{id}", require(elevated, true, func(w http.ResponseWriter, r *http.Request, u identity) {
			id := r.PathValue("id")
			if !ValidID(id) || !a.terminalOwned(id, u, elevated) {
				fail(w, 404, "终端会话不存在")
				return
			}
			after, e := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
			if e != nil && r.URL.Query().Get("after") != "" {
				fail(w, 400, "终端输出位置无效")
				return
			}
			var out terminalSnapshot
			endpoint := executorPrefix + "/sessions/" + id + "?" + url.Values{"after": {strconv.FormatUint(after, 10)}}.Encode()
			if e = a.Executor.Call(r.Context(), http.MethodGet, endpoint, nil, &out); e != nil {
				fail(w, 409, e.Error())
				return
			}
			send(w, 200, out)
		}))

		for _, action := range []string{"input", "resize"} {
			action := action
			m.HandleFunc("POST "+apiPrefix+"/sessions/{id}/"+action, require(elevated, true, func(w http.ResponseWriter, r *http.Request, u identity) {
				id := r.PathValue("id")
				if !ValidID(id) || !a.terminalOwned(id, u, elevated) {
					fail(w, 404, "终端会话不存在")
					return
				}
				var in map[string]any
				if !decode(w, r, &in) {
					return
				}
				var out map[string]bool
				if e := a.Executor.Call(r.Context(), http.MethodPost, executorPrefix+"/sessions/"+id+"/"+action, in, &out); e != nil {
					fail(w, 409, e.Error())
					return
				}
				send(w, 200, out)
			}))
		}

		m.HandleFunc("DELETE "+apiPrefix+"/sessions/{id}", require(elevated, true, func(w http.ResponseWriter, r *http.Request, u identity) {
			id := r.PathValue("id")
			if !ValidID(id) || !a.terminalOwned(id, u, elevated) {
				fail(w, 404, "终端会话不存在")
				return
			}
			var out map[string]bool
			e := a.Executor.Call(r.Context(), http.MethodDelete, executorPrefix+"/sessions/"+id, nil, &out)
			a.terminalMu.Lock()
			delete(a.terminalSessions, id)
			a.terminalMu.Unlock()
			result := "success"
			if e != nil {
				result = "failed"
			}
			_ = a.Store.Audit(u.Username, auditPrefix+".close", id, result)
			if e != nil {
				fail(w, 409, e.Error())
				return
			}
			send(w, 200, out)
		}))
	}

	register("/api/terminal", "/v1/terminal", false, "panel-task")
	register("/api/terminal/root", "/v1/terminal/root", true, "root")
}
