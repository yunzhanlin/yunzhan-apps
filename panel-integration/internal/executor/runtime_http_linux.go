//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func runtimeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/runtimes/jobs/{id}/log", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, e := readInstall(id); e != nil {
			respond(w, 404, map[string]string{"error": "安装任务不存在"})
			return
		}
		path := filepath.Join("/var/cache/panel-build", id, "build.log")
		if e := ordinary(path, false); e != nil {
			respond(w, 200, map[string]string{"content": "构建日志尚未生成"})
			return
		}
		f, e := os.Open(path)
		if e != nil {
			respond(w, 500, map[string]string{"error": "读取构建日志失败"})
			return
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			respond(w, 500, map[string]string{"error": "读取构建日志失败"})
			return
		}
		if st.Size() > 49152 {
			_, e = f.Seek(-49152, io.SeekEnd)
			if e != nil {
				respond(w, 500, map[string]string{"error": "读取构建日志失败"})
				return
			}
		}
		b, e := io.ReadAll(io.LimitReader(f, 49152))
		if e != nil {
			respond(w, 500, map[string]string{"error": "读取构建日志失败"})
			return
		}
		respond(w, 200, map[string]string{"content": string(b), "path": path})
	})

	m.HandleFunc("POST /v1/runtimes/install", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID     string `json:"job_id"`
			ReleaseID string `json:"release_id"`
			Retry     bool   `json:"retry"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		st, e := startInstall(r.Context(), in.JobID, in.ReleaseID, in.Retry)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, st)
	})
	m.HandleFunc("GET /v1/runtimes/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !core.ValidID(id) {
			respond(w, 400, map[string]string{"error": "无效任务"})
			return
		}
		st, e := readInstall(id)
		if e != nil {
			respond(w, 404, map[string]string{"error": "安装记录不存在"})
			return
		}
		if st.State == "running" || st.State == "queued" {
			unit := "panel-install@" + id + ".service"
			if release, ok := runtimecatalog.Find(st.ReleaseID); ok && release.Family == "docker" {
				unit = "panel-docker-install@" + id + ".service"
			}
			active, _ := RunCommand(r.Context(), "/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", unit)
			if strings.TrimSpace(active) == "failed" || strings.TrimSpace(active) == "inactive" {
				// The oneshot service writes its terminal state immediately before
				// systemd changes ActiveState. Re-read after systemctl so a poll that
				// crossed that boundary cannot overwrite a successful atomic write.
				if latest, er := readInstall(id); er == nil {
					st = latest
				}
				result, _ := RunCommand(r.Context(), "/usr/bin/systemctl", "show", "-p", "Result", "--value", unit)
				if (st.State == "running" || st.State == "queued") && (strings.TrimSpace(active) == "failed" || strings.TrimSpace(result) != "success") {
					st.State = "failed"
					st.Error = "构建进程已停止，核对日志后可以重试"
					_ = writeInstall(st)
				}
			}
		}
		respond(w, 200, map[string]any{"job_id": st.JobID, "release_id": st.ReleaseID, "state": st.State, "error": st.Error, "steps": st.Steps, "architecture": runtime.GOARCH})
	})
}
func phpInventory(ctx context.Context) []map[string]any {
	out := []map[string]any{}
	for _, r := range runtimecatalog.All() {
		m, e := LoadRuntime(r.ID)
		if e != nil {
			continue
		}
		status := "installed"
		if e := verifyRuntimeVersion(ctx, r); e != nil {
			status = "needs_attention"
		}
		item := map[string]any{"id": r.ID, "family": r.Family, "version": r.Version, "source": r.Source, "source_url": r.URL, "sha256": r.SHA256, "binary": r.CLI(), "status": status, "architecture": m.Architecture, "extensions": m.Extensions, "installed_at": m.InstalledAt}
		if r.Family == "php" {
			item["fpm_binary"] = r.FPM()
		}
		out = append(out, item)
	}
	return out
}

func verifyRuntimeVersion(ctx context.Context, r runtimecatalog.Release) error {
	if _, e := LoadRuntime(r.ID); e != nil {
		return e
	}
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := []string{"-r", "echo PHP_VERSION;"}
	if r.Family == "nginx" {
		args = []string{"-v"}
	}
	if r.Family == "apache" {
		args = []string{"-v"}
	}
	if r.Family == "mysql" {
		args = []string{"--no-defaults", "--version"}
	}
	if r.Family == "mariadb" {
		args = []string{"--no-defaults", "--version"}
	}
	if r.Family == "docker" {
		args = []string{"version", "--format", "{{.Server.Version}}"}
	}
	if r.Family == "redis" {
		args = []string{"--version"}
	}
	if r.Family == "node" {
		args = []string{"--version"}
	}
	cmd := exec.CommandContext(c, r.CLI(), args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	if r.Family == "mysql" {
		cmd.Env = mysqlEnv(r)
	}
	out := &boundedBuffer{max: 32768}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		return e
	}
	version := strings.TrimSpace(out.String())
	if (r.Family == "php" && version != r.Version) || (r.Family == "nginx" && !strings.Contains(version, "nginx/"+r.Version)) || (r.Family == "apache" && !strings.Contains(version, "Apache/"+r.Version)) || ((r.Family == "mysql" || r.Family == "mariadb") && !strings.Contains(version, r.Version)) || (r.Family == "docker" && !strings.Contains(version, r.Version)) || (r.Family == "redis" && !strings.Contains(version, "v="+r.Version)) || (r.Family == "node" && version != "v"+r.Version) {
		return errors.New("实际程序版本与精确版本目录不匹配")
	}
	return nil
}
