//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

func readAnalyticsHTMLRequest(id string) error {
	return readWAFEngineControl(analyticsHTMLRequests, id)
}
func verifyAnalyticsHTMLBuildContext(ctx context.Context, s *Service, id string) error {
	_, err := s.verifyAnalyticsHTMLBuild(ctx, id)
	return err
}

func (s *Service) createAnalyticsHTMLControl(directory, id string) error {
	if !core.ValidID(id) || (directory != analyticsHTMLRequests && directory != analyticsHTMLCancellations) {
		return errors.New("原生构建控制记录标识或目录无效")
	}
	if err := s.wafOwnedDirectory(directory, true); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}
	if err := readWAFEngineControl(directory, id); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) >= 64 {
		return errors.New("原生构建控制记录已达 64 份或不可读取；不会自动清除证据")
	}
	f, err := os.OpenFile(filepath.Join(directory, id+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(wafEngineRequest{1, id, core.Now()})
	_, writeErr := f.Write(append(data, '\n'))
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Service) analyticsHTMLUnitState(ctx context.Context, id string) (string, string, error) {
	out, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,Result,ExecMainStartTimestampMonotonic", "panel-analytics-html-build@"+id+".service")
	if err != nil {
		return "", "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = v
		}
	}
	if values["LoadState"] == "not-found" {
		return "missing", "", nil
	}
	state := values["ActiveState"]
	if state == "inactive" && values["ExecMainStartTimestampMonotonic"] == "0" {
		return "not-started", values["Result"], nil
	}
	if state != "active" && state != "activating" && state != "deactivating" && state != "inactive" && state != "failed" {
		return "", "", errors.New("不能核实原生构建服务状态")
	}
	return state, values["Result"], nil
}

func (s *Service) analyticsHTMLStatus(ctx context.Context, id string) (core.WAFEngineStatus, error) {
	out := core.WAFEngineStatus{JobID: id, State: "queued", Architecture: runtime.GOARCH, Engine: "njs-1.0.1/QuickJS", CRS: "", BuildOnly: true, Steps: []core.Step{}}
	if !core.ValidID(id) {
		return out, errors.New("引擎任务标识无效")
	}
	record, err := readAnalyticsHTMLBuild(id)
	if errors.Is(err, os.ErrNotExist) {
		if cancelErr := readWAFEngineControl(analyticsHTMLCancellations, id); cancelErr == nil {
			out.State, out.Error = "failed", "管理员已停止构建；未启用网站，原请求、目录与证据保留"
			return out, nil
		} else if !errors.Is(cancelErr, os.ErrNotExist) {
			return out, cancelErr
		}
		if err := readAnalyticsHTMLRequest(id); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	} else {
		if record.Format != 1 || record.Architecture != runtime.GOARCH || record.Prefix != filepath.Join(analyticsHTMLNativeRoot, id) || record.ProgramSHA != analyticsHTMLProgramSHA || record.PatchSourceSHA != analyticsNJSHeaderSourceSHA || len(record.Steps) > 32 {
			return out, errors.New("原生构建记录身份异常")
		}
		out.StartedAt, out.FinishedAt, out.Steps, out.NginxVersion = record.StartedAt, record.FinishedAt, record.Steps, record.NginxVersion
		out.ABIValidated = record.ABIValidated
		switch record.State {
		case "ready":
			if err := verifyAnalyticsHTMLBuildContext(ctx, s, id); err != nil {
				out.State, out.Error = "needs_attention", err.Error()
			} else {
				out.State, out.IntegrityVerified = "ready", true
			}
			return out, nil
		case "failed":
			out.State, out.Error = "failed", record.Error
			if out.Error == "" {
				out.Error = "构建失败；原记录与日志保留"
			}
			return out, nil
		case "building":
		default:
			return out, errors.New("原生构建记录状态异常")
		}
	}
	state, result, err := s.analyticsHTMLUnitState(ctx, id)
	if err != nil {
		return out, err
	}
	switch state {
	case "active", "activating", "deactivating":
		out.State = "running"
	case "failed":
		out.State, out.Error = "failed", "构建服务失败（"+result+"）；保留原记录，不覆盖重试"
	case "inactive":
		out.State, out.Error = "needs_attention", "构建服务已退出，但缺少可验证的完成记录；请核对日志，创建新任务"
	case "missing", "not-started":
		if record.JobID != "" {
			out.State, out.Error = "needs_attention", "构建服务不存在，原未完成记录保留；不能宣称构建成功"
		}
	}
	if out.State != "running" {
		if err := readWAFEngineControl(analyticsHTMLCancellations, id); err == nil {
			out.State, out.Error = "failed", "管理员已停止构建；未启用网站，原记录、目录与证据保留"
		} else if !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
	}
	return out, nil
}

func (s *Service) startAnalyticsHTMLBuild(ctx context.Context, id string) (core.WAFEngineStatus, error) {
	if !s.moduleInstalled("website-analytics") {
		return core.WAFEngineStatus{}, errors.New("请先安装网站分析应用")
	}
	if !core.ValidID(id) || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return core.WAFEngineStatus{}, errors.New("原生构建仅允许真实受管环境与有效任务标识")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	defer lock.Close()
	if err := readWAFEngineControl(analyticsHTMLCancellations, id); err == nil {
		return s.analyticsHTMLStatus(ctx, id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.WAFEngineStatus{}, err
	}
	if _, err := readAnalyticsHTMLBuild(id); err == nil {
		return s.analyticsHTMLStatus(ctx, id) // Attach to existing work; never overwrite its evidence.
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.WAFEngineStatus{}, err
	}
	if err := s.createAnalyticsHTMLControl(analyticsHTMLRequests, id); err != nil {
		return core.WAFEngineStatus{}, err
	}
	state, _, err := s.analyticsHTMLUnitState(ctx, id)
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	if state == "active" || state == "activating" || state == "deactivating" || state == "failed" || state == "inactive" {
		return s.analyticsHTMLStatus(ctx, id)
	}
	if state == "missing" {
		return core.WAFEngineStatus{}, errors.New("专用原生构建服务缺失；请求证据保留，不尝试其他命令")
	}
	if !s.wafBuildPackagesReady(analyticsHTMLBuildDependencies) {
		return core.WAFEngineStatus{}, errors.New("请先通过固定依赖服务安装并核对 HTML 引擎构建依赖")
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", "panel-analytics-html-build@"+id+".service"); err != nil {
		return core.WAFEngineStatus{}, err
	}
	return s.analyticsHTMLStatus(ctx, id)
}

func (s *Service) cancelAnalyticsHTMLBuild(ctx context.Context, id string) (core.WAFEngineStatus, error) {
	if !core.ValidID(id) || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return core.WAFEngineStatus{}, errors.New("只能停止真实受管环境的明确 HTML 构建任务")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	defer lock.Close()
	if record, err := readAnalyticsHTMLBuild(id); err == nil {
		if record.State != "building" {
			return s.analyticsHTMLStatus(ctx, id)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.WAFEngineStatus{}, err
	}
	// Persist before stopping. A worker currently in dependency setup or a
	// lost/replayed dispatch must never start this same identity afterward.
	if err := s.createAnalyticsHTMLControl(analyticsHTMLCancellations, id); err != nil {
		return core.WAFEngineStatus{}, err
	}
	state, _, err := s.analyticsHTMLUnitState(ctx, id)
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	if state == "active" || state == "activating" || state == "deactivating" {
		if err := readAnalyticsHTMLRequest(id); err != nil {
			return core.WAFEngineStatus{}, errors.New("正在运行的专用构建缺少所属请求证据，拒绝停止未知进程")
		}
		if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "stop", "panel-analytics-html-build@"+id+".service"); err != nil {
			return core.WAFEngineStatus{}, err
		}
	}
	return s.analyticsHTMLStatus(ctx, id)
}

func (s *Service) analyticsHTMLRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/software/website-analytics/html-engine/activate", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID string `json:"job_id"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if !core.ValidID(in.JobID) || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
			respond(w, 409, map[string]string{"error": "HTML 引擎仅允许真实受管环境和有效构建标识"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		if err := s.activateAnalyticsHTML(ctx, in.JobID); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"job_id": in.JobID, "active": true, "worker_acknowledged": true, "site_auto_injection": false})
	})
	m.HandleFunc("GET /v1/software/website-analytics/html-engine/active", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Lstat(s.systemPath("/etc/panel/analytics-html/active.json")); errors.Is(err, os.ErrNotExist) {
			respond(w, 200, map[string]any{"active": false, "state": "not-activated"})
			return
		}
		if err := s.requireAnalyticsHTMLReady(r.Context()); err != nil {
			respond(w, 200, map[string]any{"active": false, "state": "needs-attention", "error": err.Error()})
			return
		}
		var identity analyticsHTMLEngineIdentity
		if err := readAnalyticsHTMLPrivateJSON(s.systemPath("/etc/panel/analytics-html/active.json"), 64<<10, &identity); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"active": true, "state": "active", "job_id": identity.JobID, "worker_acknowledged": true})
	})
	m.HandleFunc("POST /v1/software/website-analytics/html-engine/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !readJSON(w, r, &in) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		out, err := s.cancelAnalyticsHTMLBuild(ctx, r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/software/website-analytics/html-engine/build", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID string `json:"job_id"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		out, err := s.startAnalyticsHTMLBuild(r.Context(), in.JobID)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/website-analytics/html-engine/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.analyticsHTMLStatus(r.Context(), r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/website-analytics/html-engines", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		ids := map[string]bool{}
		for _, directory := range []string{analyticsHTMLBuilds, analyticsHTMLRequests, analyticsHTMLCancellations} {
			if err := s.wafOwnedDirectory(directory, false); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) > 64 {
				respond(w, 409, map[string]string{"error": "引擎记录目录不可读取或超限"})
				return
			}
			for _, entry := range entries {
				id := strings.TrimSuffix(entry.Name(), ".json")
				if entry.IsDir() || !core.ValidID(id) || entry.Name() != id+".json" {
					respond(w, 409, map[string]string{"error": "引擎记录目录包含未知条目，拒绝不完整清单"})
					return
				}
				ids[id] = true
			}
		}
		ordered := []string{}
		for id := range ids {
			ordered = append(ordered, id)
		}
		sort.Strings(ordered)
		entries := []core.WAFEngineStatus{}
		for _, id := range ordered {
			out, err := s.analyticsHTMLStatus(ctx, id)
			if err != nil {
				out.JobID, out.State, out.Error, out.BuildOnly = id, "needs_attention", err.Error(), true
			}
			entries = append(entries, out)
		}
		respond(w, 200, map[string]any{"entries": entries, "build_only": true, "activation_requires_explicit_site_policy": true})
	})
}
