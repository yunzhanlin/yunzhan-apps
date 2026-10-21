package core

import (
	"errors"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

var nodeAppName = regexp.MustCompile(`^[\p{Han}A-Za-z0-9][\p{Han}A-Za-z0-9_. -]{0,39}$`)

type NodeApplication struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ReleaseID string `json:"release_id"`
	SiteID    string `json:"site_id"`
	SiteName  string `json:"site_name,omitempty"`
	Entry     string `json:"entry"`
	Port      int    `json:"port"`
	Starter   bool   `json:"starter,omitempty"`
	CreatedAt string `json:"created_at"`
	Status    string `json:"status,omitempty"`
	PID       int    `json:"pid,omitempty"`
}

func ValidateNodeApplication(v NodeApplication) error {
	r, ok := runtimecatalog.Find(v.ReleaseID)
	entry := filepath.Clean(v.Entry)
	if !ValidID(v.ID) || !ValidID(v.SiteID) || !nodeAppName.MatchString(v.Name) || !ok || r.Family != "node" || v.Port < 17000 || v.Port > 17999 || !filepath.IsLocal(entry) || entry != v.Entry || strings.Contains(v.Entry, `\`) || len(v.Entry) > 128 {
		return errors.New("Node.js 项目名称、版本、入口文件或端口无效")
	}
	ext := strings.ToLower(filepath.Ext(entry))
	if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
		return errors.New("Node.js 入口文件应为 js、mjs 或 cjs")
	}
	return nil
}

func (a *Server) nodeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/node/apps", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/node/apps", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/node/apps", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in NodeApplication
		if !decode(w, r, &in) {
			return
		}
		in.ID = ID()
		in.CreatedAt = Now()
		site, e := a.Store.Site(in.SiteID)
		if e != nil || site.Status == "provisioning" || site.Status == "needs_attention" {
			fail(w, 409, "请选择可用的网站目录")
			return
		}
		in.SiteName = site.Name
		if e = ValidateNodeApplication(in); e != nil {
			fail(w, 400, e.Error())
			return
		}
		var out NodeApplication
		if e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/node/apps", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "node.app.create", in.Name, "succeeded")
		send(w, 201, out)
	}))
	m.HandleFunc("POST /api/node/apps/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !ValidID(id) || (action != "start" && action != "stop" && action != "restart") {
			fail(w, 400, "Node.js 项目操作无效")
			return
		}
		var out NodeApplication
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/node/apps/"+id+"/"+action, map[string]any{}, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "node.app."+action, id, "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/node/apps/{id}/logs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) {
			fail(w, 400, "Node.js 项目标识无效")
			return
		}
		var out map[string]string
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/node/apps/"+r.PathValue("id")+"/logs", nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/node/apps/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		if !ValidID(r.PathValue("id")) || !nodeAppName.MatchString(in.ConfirmName) {
			fail(w, 400, "Node.js 删除确认无效")
			return
		}
		var out map[string]bool
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/node/apps/"+r.PathValue("id"), in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "node.app.delete", in.ConfirmName, "succeeded")
		send(w, 200, out)
	}))
}
