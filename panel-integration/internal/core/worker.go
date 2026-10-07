package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/runtimecatalog"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type ExecutorClient struct{ Client *http.Client }

func NewExecutorClient(socket string) *ExecutorClient {
	return &ExecutorClient{Client: &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}}}}
}
func (e *ExecutorClient) Call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://executor"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.Client.Do(req)
	if err != nil {
		return fmt.Errorf("执行服务连接失败: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		_ = json.Unmarshal(b, out)
		var x struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &x)
		if x.Error == "" {
			x.Error = fmt.Sprintf("执行服务返回 HTTP %d", resp.StatusCode)
		}
		return errors.New(x.Error)
	}
	return json.Unmarshal(b, out)
}

type ApplyRequest struct {
	ExpectedConfigSHA string `json:"expected_config_sha,omitempty"`
	Site              Site   `json:"site"`
	Sites             []Site `json:"sites,omitempty"`
	Enabled           bool   `json:"enabled"`
	JobID             string `json:"job_id"`
}
type ApplyResult struct {
	Status   string `json:"status"`
	Steps    []Step `json:"steps"`
	Restored bool   `json:"restored,omitempty"`
}

func RunWorker(ctx context.Context, s *Store, e *ExecutorClient) {
	go RunDatabaseWorker(ctx, s, e)
	go RunACMEWorker(ctx, s, e)
	go RunMonitoringWorker(ctx, s, e)
	go RunDatabaseConnectionWorker(ctx, s, e)
	go RunScheduleWorker(ctx, s, e)
	go RunSiteBackupWorker(ctx, s, e)
	go RunRuntimeInstallWorker(ctx, s, e)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			j, err := s.NextJob()
			if err != nil {
				if j, er := s.nextRuntimeControlJob(); er == nil {
					runRuntimeJob(ctx, s, e, j)
				}
				continue
			}
			site, err := s.Site(j.SiteID)
			if err != nil {
				log.Printf("job %s missing site: %v", j.ID, err)
				continue
			}
			if j.Kind == "archive_site" {
				var payload JobPayload
				if json.Unmarshal([]byte(j.Payload), &payload) != nil || payload.ArchiveDomain != site.Domain {
					_ = s.Finish(j, site.Status, "网站归档主域名不匹配", nil)
					continue
				}
				var archived ApplyResult
				err = e.Call(ctx, "POST", "/v1/sites/"+site.ID+"/archive", SiteArchiveRequest{Site: site, JobID: j.ID}, &archived)
				if ctx.Err() != nil {
					return
				}
				status, detail := "archived", ""
				if err != nil {
					status, detail = "needs_attention", err.Error()
				}
				if e := s.Finish(j, status, detail, archived.Steps); e != nil {
					log.Printf("persist archive job %s: %v", j.ID, e)
				}
				continue
			}
			if j.Kind == "restore_site" {
				var payload JobPayload
				if json.Unmarshal([]byte(j.Payload), &payload) != nil || payload.SiteBackup == nil || payload.SiteBackup.SiteID != site.ID {
					_ = s.Finish(j, site.Status, "网站恢复任务身份无效", nil)
					continue
				}
				var restored ApplyResult
				err = e.Call(ctx, "POST", "/v1/sites/"+site.ID+"/restore", SiteRestoreRequest{JobID: j.ID, Site: site, Backup: *payload.SiteBackup}, &restored)
				if ctx.Err() != nil {
					return
				}
				detail := ""
				if err != nil {
					detail = err.Error()
				}
				status := payload.PreviousStatus
				if status == "" {
					status = site.Status
				}
				_ = s.Finish(j, status, detail, restored.Steps)
				continue
			}
			result := ApplyResult{}
			enabled := j.Kind != "disable_site"
			previousStatus := site.Status
			if j.Kind == "create_site" || j.Kind == "switch_php" {
				var p JobPayload
				_ = json.Unmarshal([]byte(j.Payload), &p)
				site.PHPVersionID = p.ReleaseID
				if j.Kind == "switch_php" {
					previousStatus = p.PreviousStatus
					enabled = p.PreviousStatus != "stopped"
				}
			}
			expectedConfigSHA := ""
			if j.Kind == "configure_site" {
				var p JobPayload
				_ = json.Unmarshal([]byte(j.Payload), &p)
				if p.Settings == nil || p.ExpectedRevision != site.SettingsRevision {
					_ = s.Finish(j, site.Status, "网站设置版本冲突，请重新预览", nil)
					continue
				}
				site.Settings = *p.Settings
				previousStatus = p.PreviousStatus
				enabled = p.PreviousStatus != "stopped"
				expectedConfigSHA = p.ExpectedConfigSHA
			}
			if enabled && site.Settings.TLS != nil {
				material, certErr := s.CertificateMaterial(site.Settings.TLS.CertificateID)
				if certErr == nil {
					var actual Certificate
					certErr = e.Call(ctx, "POST", "/v1/certificates/install", material, &actual)
					if certErr == nil {
						expected, er := s.Certificate(material.ID)
						if er != nil {
							certErr = er
						} else if actual.ID != expected.ID || actual.Fingerprint != expected.Fingerprint || actual.ChainSHA != expected.ChainSHA {
							certErr = errors.New("执行器证书与已保存证书不匹配")
						}
					}
				}
				if certErr != nil {
					_ = s.Finish(j, site.Status, "证书准备失败: "+certErr.Error(), nil)
					continue
				}
			}
			allSites, listErr := s.Sites()
			if listErr != nil {
				_ = s.Finish(j, site.Status, "无法读取完整网站清单: "+listErr.Error(), nil)
				continue
			}
			for index := range allSites {
				if allSites[index].ID == site.ID {
					allSites[index] = site
					if !enabled {
						allSites[index].Status = "stopped"
					} else {
						allSites[index].Status = "running"
					}
				}
			}
			err = e.Call(ctx, "POST", "/v1/sites/apply", ApplyRequest{Site: site, Sites: allSites, Enabled: enabled, JobID: j.ID, ExpectedConfigSHA: expectedConfigSHA}, &result)
			detail := ""
			status := result.Status
			if err != nil {
				detail = err.Error()
				if (j.Kind == "configure_site" || j.Kind == "switch_php" || j.Kind == "disable_site" || j.Kind == "enable_site") && result.Restored {
					status = previousStatus
				} else {
					status = "needs_attention"
				}
				result.Steps = append(result.Steps, Step{Time: Now(), Message: detail})
			}
			if status == "" {
				status = "needs_attention"
				detail = "执行服务未返回可核对的站点状态"
			}
			if err = s.Finish(j, status, detail, result.Steps); err != nil {
				log.Printf("persist job %s: %v", j.ID, err)
			}
		}
	}
}

// Source builds run in dedicated executor units. Observe one build at a time
// without blocking website operations; Nginx switches and runtime lifecycle
// actions stay on the website worker to preserve their existing ordering.
func RunRuntimeInstallWorker(ctx context.Context, s *Store, e *ExecutorClient) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if j, err := s.nextRuntimeInstallJob(); err == nil {
				runRuntimeJob(ctx, s, e, j)
			}
		}
	}
}

func runRuntimeJob(ctx context.Context, s *Store, e *ExecutorClient, j Job) {
	if strings.HasPrefix(j.Kind, "software_") {
		action := strings.TrimPrefix(j.Kind, "software_")
		if (action == "install" && (j.TargetID == "pure-ftpd" || j.TargetID == "pm2-manager" || j.TargetID == "nfs-manager")) || (action == "update" && j.TargetID == "pure-ftpd") {
			dependencyCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			err := waitAppDependencies(dependencyCtx, e, j.TargetID)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					_ = s.FinishRuntime(j, err.Error(), nil)
				}
				return
			}
		}
		var payload struct {
			Settings map[string]any `json:"settings"`
			Version  string         `json:"version"`
		}
		if json.Unmarshal([]byte(j.Payload), &payload) != nil {
			_ = s.FinishRuntime(j, "软件任务参数无效", nil)
			return
		}
		var result ApplyResult
		err := e.Call(ctx, "POST", "/v1/software/"+j.TargetID+"/"+action, map[string]any{"settings": payload.Settings, "version": payload.Version}, &result)
		if ctx.Err() != nil {
			return
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		_ = s.FinishRuntime(j, detail, result.Steps)
		return
	}
	if action := lifecycleAction(j.Kind); action != "" {
		if action == "retire" {
			refs, er := s.RuntimeReferences(j.TargetID)
			if er != nil {
				_ = s.FinishRuntime(j, er.Error(), nil)
				return
			}
			for _, ref := range refs {
				if ref.Kind == "runtime_job" && ref.ID == j.ID {
					continue
				}
				_ = s.FinishRuntime(j, "执行前发现新的版本引用，卸载已停止", nil)
				return
			}
		}
		var result ApplyResult
		err := e.Call(ctx, "POST", "/v1/runtimes/lifecycle", map[string]string{"job_id": j.ID, "release_id": j.TargetID, "action": action}, &result)
		if ctx.Err() != nil {
			return
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		} else if result.Status != map[string]string{"retire": "quarantined", "restore": "installed", "purge": "purged"}[action] {
			detail = "执行器未返回匹配的运行环境状态，请核对后重试"
		}
		_ = s.finishRuntime(j, detail, result.Steps, detail != "" && result.Status != "unchanged")
		return
	}

	if j.Kind == "switch_nginx" {
		sites, err := s.Sites()
		if err != nil {
			_ = s.FinishRuntime(j, err.Error(), nil)
			return
		}
		var result ApplyResult
		err = e.Call(ctx, "POST", "/v1/nginx/switch", map[string]any{"job_id": j.ID, "release_id": j.TargetID, "sites": sites}, &result)
		if ctx.Err() != nil {
			return
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		} else if err = s.RecordNginxActive(j.TargetID); err != nil {
			detail = err.Error()
		}
		_ = s.FinishRuntime(j, detail, result.Steps)
		return
	}

	var st struct {
		State        string `json:"state"`
		Error        string `json:"error"`
		Steps        []Step `json:"steps"`
		Architecture string `json:"architecture"`
	}
	endpoint := "/v1/runtimes/install"
	args := map[string]any{"job_id": j.ID, "release_id": j.TargetID, "retry": true}
	var extension ExtensionJobPayload
	if j.Kind == "install_php_extension" {
		if er := json.Unmarshal([]byte(j.Payload), &extension); er != nil {
			_ = s.FinishRuntime(j, "扩展任务参数无效", nil)
			return
		}
		if _, ok := runtimecatalog.FindExtension(extension.ExtensionID); !ok {
			_ = s.FinishRuntime(j, "扩展不在固定目录中", nil)
			return
		}
		args["extension_id"] = extension.ExtensionID
		endpoint = "/v1/php/extensions/install"
	}
	err := e.Call(ctx, "POST", endpoint, args, &st)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		_ = s.FinishRuntime(j, err.Error(), st.Steps)
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err = e.Call(ctx, "GET", "/v1/runtimes/jobs/"+j.ID, nil, &st); err != nil {
				if ctx.Err() != nil {
					return
				}
				_ = s.FinishRuntime(j, err.Error(), st.Steps)
				return
			}
			_ = s.UpdateRuntimeSteps(j.ID, st.Steps)
			if st.State == "failed" {
				_ = s.FinishRuntime(j, st.Error, st.Steps)
				return
			}
			if st.State == "succeeded" {
				if j.Kind == "install_php_extension" {
					inventory, er := s.readPHPExtensions(ctx, e, j.TargetID)
					detail := ""
					if er != nil {
						detail = er.Error()
					} else {
						found := false
						for _, item := range inventory {
							if item.Extension.ID == extension.ExtensionID && item.Status == "installed" {
								found = true
							}
						}
						if !found {
							detail = "扩展任务结束，但实际安装核对未通过"
						}
					}
					_ = s.FinishRuntime(j, detail, st.Steps)
					return
				}
				r, ok := runtimecatalog.Find(j.TargetID)
				if !ok {
					_ = s.FinishRuntime(j, "版本不在目录中", st.Steps)
					return
				}
				if err = s.RecordInstallation(r, st.Architecture); err != nil {
					_ = s.FinishRuntime(j, err.Error(), st.Steps)
					return
				}
				_ = s.FinishRuntime(j, "", st.Steps)
				return
			}
		}
	}
}

func waitAppDependencies(ctx context.Context, executor *ExecutorClient, id string) error {
	var result struct {
		State string `json:"state"`
		Error string `json:"error"`
	}
	if err := executor.Call(ctx, "POST", "/v1/app-dependencies/"+id, nil, &result); err != nil {
		return err
	}
	for {
		if result.State == "ready" {
			return nil
		}
		if result.State == "failed" {
			return fmt.Errorf("依赖安装失败: %s", result.Error)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if err := executor.Call(ctx, "GET", "/v1/app-dependencies/"+id, nil, &result); err != nil {
			return err
		}
	}
}
