//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This read-only inventory includes stopped bindings and pending recovery guards.
// Mutations must repeat the checks under the shared lifecycle locks.
func runtimeReferences(release string) ([]core.RuntimeReference, error) {
	r, ok := runtimecatalog.Find(release)
	if !ok && release != "nginx-system" {
		return nil, errors.New("版本不在受管目录中")
	}
	out := []core.RuntimeReference{}
	if release == "nginx-system" || r.Family == "nginx" {
		id, e := activeNginx()
		if e != nil {
			return nil, e
		}
		if id == release {
			out = append(out, core.RuntimeReference{Kind: "nginx_selection", ID: id, Name: "Nginx 全局入口", State: "selected"})
		}
		guards, e := filepath.Glob(nginxSwitchDir + "/*.json")
		if e != nil {
			return nil, e
		}
		if len(guards) > 10000 {
			return nil, errors.New("Nginx 恢复记录过多，无法完成引用检查")
		}
		for _, path := range guards {
			g, e := readGuard(strings.TrimSuffix(filepath.Base(path), ".json"))
			if e != nil {
				return nil, e
			}
			if g.State == "pending" && (g.OldID == release || g.NewID == release) {
				out = append(out, core.RuntimeReference{Kind: "rollback_guard", ID: g.JobID, Name: "尚未提交的 Nginx 切换恢复", State: g.State})
			}
		}
	}
	if r.Family == "php" {
		operations, err := readPHPWorkerOperations("/var/lib/panel-executor/php-worker-operations")
		if err != nil {
			return nil, err
		}
		for _, operation := range operations {
			if operation.Input.ObservedReleaseID == release && phpWorkerOperationReference(operation.State) {
				out = append(out, core.RuntimeReference{Kind: "php_worker_operation", ID: operation.ID, Name: operation.Input.Name + " · " + operation.Action, State: operation.State})
			}
		}
		workers, err := phpWorkerRecords()
		if err != nil {
			return nil, err
		}
		for _, worker := range workers {
			if worker.ObservedReleaseID == release {
				state := "disabled"
				if worker.Enabled {
					state = "enabled"
				}
				out = append(out, core.RuntimeReference{Kind: "php_worker", ID: worker.ID, Name: worker.Name, State: state})
			}
		}
		paths, e := filepath.Glob(phpConfigRoot + "/bindings/*.json")
		if e != nil {
			return nil, e
		}
		if len(paths) > 10000 {
			return nil, errors.New("PHP 绑定数量超限")
		}
		for _, path := range paths {
			b, e := os.ReadFile(path)
			if e != nil {
				return nil, e
			}
			var site core.Site
			if e = json.Unmarshal(b, &site); e != nil || !core.ValidID(site.ID) {
				return nil, fmt.Errorf("PHP 绑定元数据异常: %s", filepath.Base(path))
			}
			if site.PHPVersionID == release {
				out = append(out, core.RuntimeReference{Kind: "php_binding", ID: site.ID, Name: site.Name + " · FPM / CLI", State: "bound"})
			}
		}
	}
	if r.Family == "mysql" {
		entries, e := os.ReadDir(mysqlRoot)
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if len(entries) > 10000 {
			return nil, errors.New("MySQL 实例数量超限")
		}
		for _, entry := range entries {
			if !entry.IsDir() || !core.ValidID(entry.Name()) {
				continue
			}
			m, e := readMySQL(entry.Name())
			if e != nil {
				return nil, e
			}
			if m.Server.ReleaseID == release {
				out = append(out, core.RuntimeReference{Kind: "mysql_manifest", ID: m.Server.ID, Name: m.Server.Name, State: "bound"})
			}
		}
		jobs, e := filepath.Glob(mysqlJobs + "/*.json")
		if e != nil {
			return nil, e
		}
		if len(jobs) > 10000 {
			return nil, errors.New("数据库任务记录过多")
		}
		for _, path := range jobs {
			j, e := readMySQLJob(strings.TrimSuffix(filepath.Base(path), ".json"))
			if e != nil {
				return nil, e
			}
			if (j.Result.State == "queued" || j.Result.State == "running") && (j.Operation.Server.ReleaseID == release || j.Operation.TargetServer.ReleaseID == release) {
				out = append(out, core.RuntimeReference{Kind: "mysql_job", ID: j.Operation.JobID, Name: j.Operation.Action, State: j.Result.State})
			}
		}
	}
	if r.Family == "redis" {
		entries, e := os.ReadDir(redisRoot)
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if len(entries) > 10000 {
			return nil, errors.New("Redis 实例数量超限")
		}
		for _, entry := range entries {
			if !entry.IsDir() || !core.ValidID(entry.Name()) {
				continue
			}
			instance, e := readRedis(entry.Name())
			if e != nil {
				return nil, e
			}
			if instance.ReleaseID == release {
				out = append(out, core.RuntimeReference{Kind: "redis_manifest", ID: instance.ID, Name: instance.Name, State: "bound"})
			}
		}
	}
	if r.Family == "node" {
		entries, e := os.ReadDir(nodeRoot)
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if len(entries) > 10000 {
			return nil, errors.New("Node.js 项目数量超限")
		}
		for _, entry := range entries {
			if !entry.IsDir() || !core.ValidID(entry.Name()) {
				continue
			}
			app, e := readNode(entry.Name())
			if e != nil {
				return nil, e
			}
			if app.ReleaseID == release {
				out = append(out, core.RuntimeReference{Kind: "node_manifest", ID: app.ID, Name: app.Name, State: "bound"})
			}
		}
	}
	if r.Family == "mariadb" {
		entries, e := os.ReadDir(mariadbRoot)
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if len(entries) > 10000 {
			return nil, errors.New("MariaDB 实例数量超限")
		}
		for _, entry := range entries {
			if !entry.IsDir() || !core.ValidID(entry.Name()) {
				continue
			}
			instance, e := readMariaDB(entry.Name())
			if e != nil {
				return nil, e
			}
			if instance.ReleaseID == release {
				out = append(out, core.RuntimeReference{Kind: "mariadb_manifest", ID: instance.ID, Name: instance.Name, State: "bound"})
			}
		}
	}
	paths, e := filepath.Glob(installState + "/*.json")
	if e != nil {
		return nil, e
	}
	if len(paths) > 10000 {
		return nil, errors.New("安装任务记录过多")
	}
	for _, path := range paths {
		st, e := readInstall(strings.TrimSuffix(filepath.Base(path), ".json"))
		if e != nil {
			return nil, e
		}
		if st.ReleaseID == release && (st.State == "queued" || st.State == "running") {
			out = append(out, core.RuntimeReference{Kind: "install_job", ID: st.JobID, Name: "版本安装", State: st.State})
		}
	}
	prefix := r.Prefix() + "/"
	if release == "nginx-system" {
		prefix = "/usr/sbin/nginx"
	}
	processes, e := os.ReadDir("/proc")
	if e != nil {
		return nil, e
	}
	for _, entry := range processes {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		exe, e := os.Readlink("/proc/" + entry.Name() + "/exe")
		if e != nil {
			continue
		}
		if (release == "nginx-system" && exe == prefix) || (release != "nginx-system" && strings.HasPrefix(exe, prefix)) {
			out = append(out, core.RuntimeReference{Kind: "process", ID: entry.Name(), Name: filepath.Base(exe), State: "running"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
func runtimeReferenceRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/runtimes/references/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, e := runtimeReferences(r.PathValue("id"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
}
