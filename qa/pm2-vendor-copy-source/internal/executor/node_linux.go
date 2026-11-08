//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const nodeRoot = "/etc/panel/node"

func nodeConfig(id string) string { return filepath.Join(nodeRoot, id) }
func nodeUnit(id string) string   { return "panel-node@" + id + ".service" }
func nodeProject(a core.NodeApplication) string {
	return filepath.Join("/srv/panel/sites", a.SiteID, "public")
}

func readNode(id string) (core.NodeApplication, error) {
	var app core.NodeApplication
	if !core.ValidID(id) {
		return app, errors.New("Node.js 项目标识无效")
	}
	b, e := os.ReadFile(filepath.Join(nodeConfig(id), "instance.json"))
	if e == nil {
		e = json.Unmarshal(b, &app)
	}
	if e == nil && (app.ID != id || core.ValidateNodeApplication(app) != nil) {
		e = errors.New("Node.js 项目清单不匹配")
	}
	return app, e
}

func ServeNode(id string) error {
	lock, e := runtimeUseLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	app, e := readNode(id)
	if e != nil {
		return e
	}
	release, ok := runtimecatalog.Find(app.ReleaseID)
	if !ok || release.Family != "node" {
		return errors.New("Node.js 版本不在固定目录")
	}
	if _, e = LoadRuntime(release.ID); e != nil {
		return e
	}
	project := nodeProject(app)
	if e = ordinary(project, true); e != nil {
		return e
	}
	entry := filepath.Join(project, app.Entry)
	if e = ordinary(entry, false); e != nil {
		return e
	}
	u, e := user.Lookup(siteUser(app.SiteID))
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	groups := []int{gid}
	if web, e := user.LookupGroup("www-data"); e == nil {
		if n, er := strconv.Atoi(web.Gid); er == nil {
			groups = append(groups, n)
		}
	}
	if e = os.Chdir(project); e != nil {
		return e
	}
	if e = syscall.Setgroups(groups); e != nil {
		return e
	}
	if e = syscall.Setgid(gid); e != nil {
		return e
	}
	if e = syscall.Setuid(uid); e != nil {
		return e
	}
	binary := release.CLI()
	return syscall.Exec(binary, []string{binary, entry}, []string{"PATH=" + release.Prefix() + "/bin:/usr/bin:/bin", "LANG=C", "HOME=/srv/panel/sites/" + app.SiteID + "/private", "NODE_ENV=production", "HOST=127.0.0.1", "PORT=" + strconv.Itoa(app.Port)})
}

func nodeReady(ctx context.Context, app core.NodeApplication) error {
	for i := 0; i < 50; i++ {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", app.Port), 200*time.Millisecond)
		if e == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("Node.js 项目未在期限内监听所选回环端口，请核对日志与入口文件")
}

func createNode(ctx context.Context, app core.NodeApplication) (ret error) {
	if e := core.ValidateNodeApplication(app); e != nil {
		return e
	}
	release, ok := runtimecatalog.Find(app.ReleaseID)
	if !ok || release.Family != "node" {
		return errors.New("Node.js 版本不在固定目录")
	}
	if _, e := LoadRuntime(release.ID); e != nil {
		return errors.New("请先安装所选 Node.js 版本")
	}
	entries, e := os.ReadDir(nodeRoot)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		other, er := readNode(entry.Name())
		if er != nil {
			continue
		}
		count++
		if other.Name == app.Name {
			return errors.New("Node.js 项目名称已被使用")
		}
		if other.Port == app.Port {
			return errors.New("Node.js 项目端口已被使用")
		}
	}
	if count >= 32 {
		return errors.New("Node.js 项目数量已达到 32 个上限")
	}
	listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", app.Port))
	if e != nil {
		return errors.New("Node.js 项目端口已被其他服务使用")
	}
	listener.Close()
	project := nodeProject(app)
	if e = ordinary(project, true); e != nil {
		return errors.New("网站项目目录不存在")
	}
	marker := filepath.Join(filepath.Dir(project), ".panel-site.json")
	if e = ordinary(marker, false); e != nil {
		return errors.New("网站目录归属标记不存在")
	}
	var owner map[string]string
	b, e := os.ReadFile(marker)
	if e != nil || json.Unmarshal(b, &owner) != nil || owner["id"] != app.SiteID {
		return errors.New("网站目录归属不匹配")
	}
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "start", "panel-site-user@"+app.SiteID+".service"); e != nil {
		return e
	}
	u, e := user.Lookup(siteUser(app.SiteID))
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	entry := filepath.Join(project, app.Entry)
	if _, e = os.Lstat(entry); errors.Is(e, os.ErrNotExist) {
		if !app.Starter {
			return errors.New("Node.js 入口文件不存在")
		}
		starter := fmt.Sprintf("const http=require('http');const host=process.env.HOST||'127.0.0.1';const port=Number(process.env.PORT||%d);http.createServer((req,res)=>{res.setHeader('content-type','application/json; charset=utf-8');res.end(JSON.stringify({ok:true,service:%q,node:process.version}));}).listen(port,host,()=>console.log(`ready http://${host}:${port}`));\n", app.Port, app.Name)
		if e = atomicWrite(entry, []byte(starter), 0640); e != nil {
			return e
		}
		if e = os.Chown(entry, uid, gid); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if e = ordinary(entry, false); e != nil {
		return e
	}
	cfg := nodeConfig(app.ID)
	if _, e = os.Lstat(cfg); !errors.Is(e, os.ErrNotExist) {
		return errors.New("Node.js 项目配置目录已存在")
	}
	if e = os.MkdirAll(cfg, 0700); e != nil {
		return e
	}
	committed := false
	defer func() {
		if ret != nil && !committed {
			_, _ = RunCommand(context.Background(), "/usr/bin/systemctl", "disable", "--now", nodeUnit(app.ID))
			_ = os.RemoveAll(cfg)
		}
	}()
	b, _ = json.Marshal(app)
	if e = atomicWrite(filepath.Join(cfg, "instance.json"), b, 0600); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "enable", "--now", nodeUnit(app.ID)); e != nil {
		return e
	}
	if e = nodeReady(ctx, app); e != nil {
		return e
	}
	committed = true
	return nil
}

func inspectNode(ctx context.Context, app core.NodeApplication) core.NodeApplication {
	app.Status = "stopped"
	state, _ := RunCommand(ctx, "/usr/bin/systemctl", "is-active", nodeUnit(app.ID))
	if strings.TrimSpace(state) != "active" {
		return app
	}
	app.Status = "running"
	pid, _ := RunCommand(ctx, "/usr/bin/systemctl", "show", "-p", "MainPID", "--value", nodeUnit(app.ID))
	app.PID, _ = strconv.Atoi(strings.TrimSpace(pid))
	if e := nodeReady(ctx, app); e != nil {
		app.Status = "needs_attention"
	}
	return app
}
func listNode(ctx context.Context) ([]core.NodeApplication, error) {
	entries, e := os.ReadDir(nodeRoot)
	if errors.Is(e, os.ErrNotExist) {
		return []core.NodeApplication{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []core.NodeApplication{}
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		app, er := readNode(entry.Name())
		if er == nil {
			out = append(out, inspectNode(ctx, app))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *Service) nodeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/node/apps", func(w http.ResponseWriter, r *http.Request) {
		items, e := listNode(r.Context())
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"apps": items})
	})
	m.HandleFunc("POST /v1/node/apps", func(w http.ResponseWriter, r *http.Request) {
		var in core.NodeApplication
		if !readJSON(w, r, &in) {
			return
		}
		if e := createNode(r.Context(), in); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, inspectNode(r.Context(), in))
	})
	m.HandleFunc("POST /v1/node/apps/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		app, e := readNode(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "Node.js 项目不存在"})
			return
		}
		action := r.PathValue("action")
		if action != "start" && action != "stop" && action != "restart" {
			respond(w, 400, map[string]string{"error": "Node.js 操作无效"})
			return
		}
		if _, e = RunCommand(r.Context(), "/usr/bin/systemctl", action, nodeUnit(app.ID)); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		if action != "stop" {
			if e = nodeReady(r.Context(), app); e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		respond(w, 200, inspectNode(r.Context(), app))
	})
	m.HandleFunc("GET /v1/node/apps/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		if _, e := readNode(r.PathValue("id")); e != nil {
			respond(w, 404, map[string]string{"error": "Node.js 项目不存在"})
			return
		}
		out, e := RunCommand(r.Context(), "/usr/bin/journalctl", "-u", nodeUnit(r.PathValue("id")), "-n", "200", "--no-pager", "--output=short-iso")
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]string{"content": out})
	})
	m.HandleFunc("DELETE /v1/node/apps/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		app, e := readNode(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "Node.js 项目不存在"})
			return
		}
		if in.ConfirmName != app.Name {
			respond(w, 409, map[string]string{"error": "请输入项目名称确认删除"})
			return
		}
		if _, e = RunCommand(r.Context(), "/usr/bin/systemctl", "disable", "--now", nodeUnit(app.ID)); e != nil && !strings.Contains(e.Error(), "not loaded") {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		if e = ordinary(nodeConfig(app.ID), true); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		if e = os.RemoveAll(nodeConfig(app.ID)); e != nil {
			respond(w, 500, map[string]string{"error": "删除 Node.js 项目配置失败"})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
}
