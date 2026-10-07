//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

const wafEngineRequests = "/var/lib/panel-executor/waf-engine-requests"
const wafEngineCancellations = "/var/lib/panel-executor/waf-engine-cancellations"

type wafEngineRequest struct {
	Format    int    `json:"format"`
	JobID     string `json:"job_id"`
	CreatedAt string `json:"created_at"`
}

func readWAFEngineRequest(id string) error {
	return readWAFEngineControl(wafEngineRequests, id)
}

func readWAFEngineControl(directory, id string) error {
	if !core.ValidID(id) {
		return errors.New("引擎任务标识无效")
	}
	path := filepath.Join(directory, id+".json")
	if err := ownedRuntimePath(path, false); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1024 {
		return errors.New("原生构建请求记录类型、权限或大小异常")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("原生构建请求记录所有者或链接数异常")
	}
	d := json.NewDecoder(io.LimitReader(f, 1025))
	d.DisallowUnknownFields()
	var request wafEngineRequest
	if err := d.Decode(&request); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF || request.Format != 1 || request.JobID != id || request.CreatedAt == "" {
		return errors.New("原生构建请求身份或内容异常")
	}
	if _, err := time.Parse(time.RFC3339, request.CreatedAt); err != nil {
		return errors.New("原生构建请求时间异常")
	}
	return nil
}

func (s *Service) createWAFEngineControl(directory, id string) error {
	if !core.ValidID(id) || (directory != wafEngineRequests && directory != wafEngineCancellations) {
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

func (s *Service) wafEngineUnitState(ctx context.Context, id string) (string, string, error) {
	out, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,Result,ExecMainStartTimestampMonotonic", "panel-waf-engine-build@"+id+".service")
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

func (s *Service) wafEngineStatus(ctx context.Context, id string) (core.WAFEngineStatus, error) {
	out := core.WAFEngineStatus{JobID: id, State: "queued", Architecture: runtime.GOARCH, Engine: wafBodyEngineVersion, CRS: wafBodyCRSVersion, BuildOnly: true, Steps: []core.Step{}}
	if !core.ValidID(id) {
		return out, errors.New("引擎任务标识无效")
	}
	record, err := readWAFBuildRecord(id)
	if errors.Is(err, os.ErrNotExist) {
		if cancelErr := readWAFEngineControl(wafEngineCancellations, id); cancelErr == nil {
			out.State, out.Error = "failed", "管理员已停止构建；未启用网站，原请求、目录与证据保留"
			return out, nil
		} else if !errors.Is(cancelErr, os.ErrNotExist) {
			return out, cancelErr
		}
		if err := readWAFEngineRequest(id); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	} else {
		if record.Format != 1 || record.Architecture != runtime.GOARCH || record.Prefix != filepath.Join(wafNativeEngines, id) || record.Engine != wafBodyEngineVersion || record.Connector != wafBodyConnectorVersion || record.CRS != wafBodyCRSVersion || len(record.Steps) > 32 {
			return out, errors.New("原生构建记录身份异常")
		}
		out.StartedAt, out.FinishedAt, out.Steps, out.NginxVersion = record.StartedAt, record.FinishedAt, record.Steps, record.NginxVersion
		out.ABIValidated = record.ABIValidated
		switch record.State {
		case "ready":
			if err := verifyWAFEngineBuildContext(ctx, id); err != nil {
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
	state, result, err := s.wafEngineUnitState(ctx, id)
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
		if err := readWAFEngineControl(wafEngineCancellations, id); err == nil {
			out.State, out.Error = "failed", "管理员已停止构建；未启用网站，原记录、目录与证据保留"
		} else if !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
	}
	return out, nil
}

func (s *Service) startWAFEngineBuild(ctx context.Context, id string) (core.WAFEngineStatus, error) {
	if !core.ValidID(id) || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return core.WAFEngineStatus{}, errors.New("原生构建仅允许真实受管环境与有效任务标识")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	defer lock.Close()
	if err := readWAFEngineControl(wafEngineCancellations, id); err == nil {
		return s.wafEngineStatus(ctx, id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.WAFEngineStatus{}, err
	}
	if _, err := readWAFBuildRecord(id); err == nil {
		return s.wafEngineStatus(ctx, id) // Attach to existing work; never overwrite its evidence.
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.WAFEngineStatus{}, err
	}
	if err := s.createWAFEngineControl(wafEngineRequests, id); err != nil {
		return core.WAFEngineStatus{}, err
	}
	state, _, err := s.wafEngineUnitState(ctx, id)
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	if state == "active" || state == "activating" || state == "deactivating" || state == "failed" || state == "inactive" {
		return s.wafEngineStatus(ctx, id)
	}
	if state == "missing" {
		return core.WAFEngineStatus{}, errors.New("专用原生构建服务缺失；请求证据保留，不尝试其他命令")
	}
	if !s.wafBuildDependenciesReady() {
		return core.WAFEngineStatus{}, errors.New("请先通过固定依赖服务安装并核对 WAF 构建依赖")
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", "panel-waf-engine-build@"+id+".service"); err != nil {
		return core.WAFEngineStatus{}, err
	}
	return s.wafEngineStatus(ctx, id)
}

func (s *Service) cancelWAFEngineBuild(ctx context.Context, id string) (core.WAFEngineStatus, error) {
	if !core.ValidID(id) || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return core.WAFEngineStatus{}, errors.New("只能停止真实受管环境的明确 WAF 构建任务")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	defer lock.Close()
	if record, err := readWAFBuildRecord(id); err == nil {
		if record.State != "building" {
			return s.wafEngineStatus(ctx, id)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.WAFEngineStatus{}, err
	}
	// Persist before stopping. A worker currently in dependency setup or a
	// lost/replayed dispatch must never start this same identity afterward.
	if err := s.createWAFEngineControl(wafEngineCancellations, id); err != nil {
		return core.WAFEngineStatus{}, err
	}
	state, _, err := s.wafEngineUnitState(ctx, id)
	if err != nil {
		return core.WAFEngineStatus{}, err
	}
	if state == "active" || state == "activating" || state == "deactivating" {
		if err := readWAFEngineRequest(id); err != nil {
			return core.WAFEngineStatus{}, errors.New("正在运行的专用构建缺少所属请求证据，拒绝停止未知进程")
		}
		if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "stop", "panel-waf-engine-build@"+id+".service"); err != nil {
			return core.WAFEngineStatus{}, err
		}
	}
	return s.wafEngineStatus(ctx, id)
}

func (s *Service) wafEngineRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/software/nginx-waf/engine/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !readJSON(w, r, &in) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		out, err := s.cancelWAFEngineBuild(ctx, r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/software/nginx-waf/engine/build", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID string `json:"job_id"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		out, err := s.startWAFEngineBuild(r.Context(), in.JobID)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/nginx-waf/engine/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.wafEngineStatus(r.Context(), r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/nginx-waf/engines", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		ids := map[string]bool{}
		for _, directory := range []string{wafEngineJobs, wafEngineRequests, wafEngineCancellations} {
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
			out, err := s.wafEngineStatus(ctx, id)
			if err != nil {
				out.JobID, out.State, out.Error, out.BuildOnly = id, "needs_attention", err.Error(), true
			}
			entries = append(entries, out)
		}
		respond(w, 200, map[string]any{"entries": entries, "build_only": true, "activation_requires_explicit_site_policy": true})
	})
}
