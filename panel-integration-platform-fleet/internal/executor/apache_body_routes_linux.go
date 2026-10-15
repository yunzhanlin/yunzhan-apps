//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

func (s *Service) apacheBodyEngineUnitState(ctx context.Context, id string) (string, string, error) {
	if !core.ValidID(id) {
		return "", "", errors.New("Apache 构建服务标识无效")
	}
	out, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,Result,ExecMainStartTimestampMonotonic", "panel-apache-body-build@"+id+".service")
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

func (s *Service) apacheBodyEngineStatus(ctx context.Context, id string) (core.ApacheBodyEngineStatus, error) {
	out := core.ApacheBodyEngineStatus{JobID: id, State: "queued", Architecture: runtime.GOARCH, Engine: apacheBodyEngineVersion, CRS: wafBodyCRSVersion, YAJL: apacheBodyYAJLVersion, BuildOnly: true, Steps: []core.Step{}}
	if !core.ValidID(id) {
		return out, errors.New("引擎任务标识无效")
	}
	record, err := readApacheBodyBuildRecord(id)
	if errors.Is(err, os.ErrNotExist) {
		if cancelErr := readApacheBodyControl(apacheBodyCancellations, id); cancelErr == nil {
			out.State, out.Error = "failed", "管理员已停止构建；未启用网站，原请求、目录与证据保留"
			return out, nil
		} else if !errors.Is(cancelErr, os.ErrNotExist) {
			return out, cancelErr
		}
		if err := readApacheBodyControl(apacheBodyRequests, id); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	} else {
		if record.Format != 1 || record.Architecture != runtime.GOARCH || record.Prefix != filepath.Join(apacheBodyEngines, id) || (record.Engine != apacheBodyEngineVersion && record.Engine != "2.9.15-yz4") || record.YAJL != apacheBodyYAJLVersion || record.CRS != wafBodyCRSVersion || len(record.Steps) > 48 {
			return out, errors.New("原生构建记录身份异常")
		}
		out.StartedAt, out.FinishedAt, out.Steps, out.ApacheVersion = record.StartedAt, record.FinishedAt, record.Steps, record.ApacheVersion
		out.Engine = record.Engine // Never relabel an older stored program as YZ5.
		if (record.Engine == "2.9.15-yz4" || record.CompilerCollection != apacheBodyCompilerCollectionContract) && record.State == "ready" {
			out.State, out.Error = "needs_attention", "旧构建记录保留，缺少当前编译进程回收契约，不允许启用；尚未核实保留程序完整性"
			if err := apacheBodyRetainedRecordContract(record); err != nil {
				out.Error += "：" + err.Error()
				return out, nil
			}
			if err := verifyApacheBodyRetainedBytes(ctx, record); err != nil {
				out.Error += "：" + err.Error()
				return out, nil
			}
			out.State, out.HistoricalIntegrityVerified = "retained_unsupported", true
			out.Error = "旧构建的原程序、规则和许可完整性已核实，仅保留查阅；不证明新会话及退出中的子进程均已回收，不能在当前发布启用。请显式创建符合当前回收契约的新构建，原证据未迁移、删除或覆盖。"
			return out, nil
		}
		out.ABIValidated, out.HardeningValidated, out.CompilerCollected = record.ABIValidated, record.HardeningValidated, record.CompilerCollected
		switch record.State {
		case "ready":
			if err := verifyApacheBodyBuildContext(ctx, id); err != nil {
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
	state, result, err := s.apacheBodyEngineUnitState(ctx, id)
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
		if err := readApacheBodyControl(apacheBodyCancellations, id); err == nil {
			out.State, out.Error = "failed", "管理员已停止构建；未启用网站，原记录、目录与证据保留"
		} else if !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
	}
	return out, nil
}

func (s *Service) startApacheBodyEngineBuild(ctx context.Context, id string) (core.ApacheBodyEngineStatus, error) {
	if !core.ValidID(id) || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return core.ApacheBodyEngineStatus{}, errors.New("原生构建仅允许真实受管环境与有效任务标识")
	}
	lock, err := s.apacheWAFTransactionService().lockWAFConfiguration()
	if err != nil {
		return core.ApacheBodyEngineStatus{}, err
	}
	defer lock.Close()
	if err := readApacheBodyControl(apacheBodyCancellations, id); err == nil {
		return s.apacheBodyEngineStatus(ctx, id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.ApacheBodyEngineStatus{}, err
	}
	if _, err := readApacheBodyBuildRecord(id); err == nil {
		return s.apacheBodyEngineStatus(ctx, id) // Attach to existing work; never overwrite its evidence.
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.ApacheBodyEngineStatus{}, err
	}
	if err := createApacheBodyControl(apacheBodyRequests, id); err != nil {
		return core.ApacheBodyEngineStatus{}, err
	}
	state, _, err := s.apacheBodyEngineUnitState(ctx, id)
	if err != nil {
		return core.ApacheBodyEngineStatus{}, err
	}
	if state == "active" || state == "activating" || state == "deactivating" || state == "failed" || state == "inactive" {
		return s.apacheBodyEngineStatus(ctx, id)
	}
	if state == "missing" {
		return core.ApacheBodyEngineStatus{}, errors.New("专用原生构建服务缺失；请求证据保留，不尝试其他命令")
	}
	if err := s.apacheBodyBuildReady(ctx); err != nil {
		return core.ApacheBodyEngineStatus{}, errors.New("请先通过固定依赖服务安装并核对 WAF 构建依赖")
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", "panel-apache-body-build@"+id+".service"); err != nil {
		return core.ApacheBodyEngineStatus{}, err
	}
	return s.apacheBodyEngineStatus(ctx, id)
}

func (s *Service) cancelApacheBodyEngineBuild(ctx context.Context, id string) (core.ApacheBodyEngineStatus, error) {
	if !core.ValidID(id) || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return core.ApacheBodyEngineStatus{}, errors.New("只能停止真实受管环境的明确 WAF 构建任务")
	}
	lock, err := s.apacheWAFTransactionService().lockWAFConfiguration()
	if err != nil {
		return core.ApacheBodyEngineStatus{}, err
	}
	defer lock.Close()
	if record, err := readApacheBodyBuildRecord(id); err == nil {
		if record.State != "building" {
			return s.apacheBodyEngineStatus(ctx, id)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.ApacheBodyEngineStatus{}, err
	}
	// Persist before stopping. A worker currently in dependency setup or a
	// lost/replayed dispatch must never start this same identity afterward.
	if err := createApacheBodyControl(apacheBodyCancellations, id); err != nil {
		return core.ApacheBodyEngineStatus{}, err
	}
	state, _, err := s.apacheBodyEngineUnitState(ctx, id)
	if err != nil {
		return core.ApacheBodyEngineStatus{}, err
	}
	if state == "active" || state == "activating" || state == "deactivating" {
		if err := readApacheBodyControl(apacheBodyRequests, id); err != nil {
			return core.ApacheBodyEngineStatus{}, errors.New("正在运行的专用构建缺少所属请求证据，拒绝停止未知进程")
		}
		if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "stop", "panel-apache-body-build@"+id+".service"); err != nil {
			return core.ApacheBodyEngineStatus{}, err
		}
	}
	return s.apacheBodyEngineStatus(ctx, id)
}

func (s *Service) apacheBodyEngineRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/software/apache-waf/body-engine/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !readJSON(w, r, &in) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		out, err := s.cancelApacheBodyEngineBuild(ctx, r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/software/apache-waf/body-engine/build", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID string `json:"job_id"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		out, err := s.startApacheBodyEngineBuild(r.Context(), in.JobID)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/apache-waf/body-engine/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.apacheBodyEngineStatus(r.Context(), r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/apache-waf/body-engines", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		ids := map[string]bool{}
		for _, directory := range []string{apacheBodyJobs, apacheBodyRequests, apacheBodyCancellations} {
			if err := apacheBodyOwnedAncestors(directory); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
			st, statErr := os.Lstat(directory)
			if statErr != nil || st.Mode().Perm() != 0700 {
				respond(w, 409, map[string]string{"error": "Apache 构建记录目录不是私有目录"})
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
		entries := []core.ApacheBodyEngineStatus{}
		for _, id := range ordered {
			out, err := s.apacheBodyEngineStatus(ctx, id)
			if err != nil {
				out.JobID, out.State, out.Error, out.BuildOnly = id, "needs_attention", err.Error(), true
			}
			entries = append(entries, out)
		}
		respond(w, 200, map[string]any{"entries": entries, "build_only": true, "activation_requires_explicit_site_policy": true})
	})
}
