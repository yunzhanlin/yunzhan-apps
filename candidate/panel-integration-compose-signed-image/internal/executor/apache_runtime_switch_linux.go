//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

const apacheRuntimeOperations = "/var/lib/panel-executor/apache-runtime-switches"

type apacheRuntimeOperation struct {
	Request       core.ApacheRuntimeDispatch `json:"request"`
	State         string                     `json:"state"`
	TransactionID string                     `json:"transaction_id,omitempty"`
	Error         string                     `json:"error,omitempty"`
	Result        core.ApplyResult           `json:"result"`
}

type apacheRuntimePlan struct {
	Changes    []wafConfigChange
	Previous   core.WAFConfig
	Next       core.WAFConfig
	WAFVersion string
	Domain     string
}

func readApacheRuntimeOperation(id string) (apacheRuntimeOperation, error) {
	var out apacheRuntimeOperation
	if !core.ValidID(id) {
		return out, errors.New("Apache 运行任务标识无效")
	}
	path := filepath.Join(apacheRuntimeOperations, id+".json")
	if err := apacheBodyOwnedAncestors(filepath.Dir(path)); err != nil {
		return out, err
	}
	if err := ownedRuntimePath(path, false); err != nil {
		return out, err
	}
	raw, err := apacheWAFReadStableFile(path, 64<<10)
	if err != nil {
		return out, err
	}
	if err := apacheBodyDecodeJSON(raw, &out); err != nil {
		return out, err
	}
	if out.Request.JobID != id || out.Request.ReleaseID != runtimecatalog.ApacheCurrentID || !core.ValidID(out.Request.ActorID) || out.Request.AccessRevision < 1 || len(out.Result.Steps) > 64 {
		return out, errors.New("Apache 运行任务身份或回执异常")
	}
	switch out.State {
	case "planning", "applying", "committed", "failed":
	default:
		return out, errors.New("Apache 运行任务状态未知")
	}
	return out, nil
}

func saveApacheRuntimeOperation(op apacheRuntimeOperation, create bool) error {
	raw, err := json.Marshal(op)
	if err != nil || len(raw) > 64<<10 {
		return errors.New("Apache 运行任务超过有界回执限制")
	}
	path := filepath.Join(apacheRuntimeOperations, op.Request.JobID+".json")
	if !create {
		return atomicWrite(path, raw, 0600)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(raw)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	return syncRuntimeDirs(apacheRuntimeOperations)
}

func (s *Service) planApacheRuntimeSwitch(ctx context.Context, previous, next runtimecatalog.Release, engineID string) (apacheRuntimePlan, error) {
	var plan apacheRuntimePlan
	txs := s.apacheWAFTransactionService()
	paths := txs.apacheWAFConfigurationPaths()
	backups := []fileBackup{}
	for _, path := range paths {
		b, err := txs.apacheWAFStableBackup(path)
		if err != nil {
			return plan, err
		}
		backups = append(backups, b)
	}
	if !backups[0].existed {
		return plan, errors.New("Apache 原完整配置缺失，未切换")
	}
	source := string(backups[0].data)
	base := source
	plan.Previous = core.DefaultApacheWAFConfig()
	plan.Next = core.DefaultApacheWAFConfig()
	var manifest any
	rules := string(backups[1].data)
	if backups[2].existed {
		if _, err := apacheBodySiteManifestDocument(backups[2].data); err != nil {
			return plan, err
		}
		var installed struct {
			ID, Version string
			Settings    map[string]any
		}
		if json.Unmarshal(backups[2].data, &installed) != nil || installed.ID != "apache-waf" {
			return plan, errors.New("Apache 防护原安装身份不可核对")
		}
		cfg, err := core.DecodeApacheWAFVersionConfig(installed.Settings, installed.Version)
		if err != nil {
			return plan, err
		}
		if installed.Version != core.ApacheWAFVersion && !core.ApacheWAFNativeVersion(installed.Version) {
			return plan, errors.New("Apache 旧防护应用需先完成其签名更新，未改变运行版本")
		}
		if err := s.verifyApacheWAFHealth(ctx, installed.Version, installed.Settings); err != nil {
			return plan, err
		}
		domain, err := apacheWAFConfigurationFilesMatchVersion(source, cfg, filepath.Join(previous.Prefix(), "modules/mod_remoteip.so"), paths[1], installed.Version)
		if err != nil {
			return plan, err
		}
		plan.Previous = cfg
		plan.WAFVersion = installed.Version
		plan.Domain = domain
		plan.Next, err = apacheRuntimePolicy(cfg, engineID)
		if err != nil {
			return plan, err
		}
		if cfg.ApacheCC != nil && installed.Version == core.ApacheWAFCCLogArchiveVersion {
			record, err := readApacheBodyBuildRecord(engineID)
			if err != nil || record.Format != 3 || record.CCEngine != apacheCCRotationEngineVersion {
				return plan, errors.New("Apache 2.5.1 防护须选择保留当前 CC 日志与封存契约的新版引擎")
			}
		}
		if err := s.verifyApacheBodyTransitionForReleases(ctx, cfg, plan.Next, previous.Version, next.Version); err != nil {
			return plan, err
		}
		base, err = transitionApacheBodySource(source, cfg, core.DefaultApacheWAFConfig())
		if err != nil {
			return plan, err
		}
		base, err = apacheRuntimeSource(base, previous, next)
		if err != nil {
			return plan, err
		}
		if core.ApacheWAFNativeVersion(installed.Version) {
			base, rules, err = apacheNativeCandidateVersion(base, core.DefaultApacheWAFConfig(), plan.Next, filepath.Join(next.Prefix(), "modules/mod_remoteip.so"), installed.Version)
		} else {
			base, rules, err = apacheMetadataSitePolicy(base, plan.Next, installed.Version, filepath.Join(next.Prefix(), "modules/mod_remoteip.so"))
		}
		if err != nil {
			return plan, err
		}
		manifest, err = apacheBodySiteManifest(backups[2].data, plan.Next)
		if err != nil {
			return plan, err
		}
		if err := s.prepareApacheBodyStorage(ctx, plan.Next); err != nil {
			return plan, err
		}
		if apacheCCPolicyMayLog(plan.Next) {
			if err := verifyApacheCCLogStorage(false); err != nil {
				return plan, err
			}
		}
		plan.Changes, err = txs.planApacheWAFTransaction(backups, base, rules, manifest, false)
		return plan, err
	}
	if backups[1].existed || engineID != "" || apacheNativeDirectivesPresent(source) {
		return plan, errors.New("Apache 无防护安装记录却存在规则、模块或引擎选择，未切换")
	}
	var err error
	if _, err = prepareApacheWAFTrustedProxySource(source, nil, filepath.Join(previous.Prefix(), "modules/mod_remoteip.so")); err != nil {
		return plan, err
	}
	base, err = apacheRuntimeSource(source, previous, next)
	if err != nil {
		return plan, err
	}
	for index, b := range backups {
		nextData := b.data
		if index == 0 {
			nextData = []byte(base)
		}
		plan.Changes = append(plan.Changes, wafConfigChange{Path: b.path, OldData: b.data, OldExists: b.existed, OldMode: b.mode, OldOwner: b.owner, NextData: nextData, NextExists: b.existed, NextMode: b.mode, NextOwner: b.owner})
	}
	return plan, nil
}

func (s *Service) apacheRunningRelease(ctx context.Context) (string, string, error) {
	out, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "panel-apache", "--property=ActiveState,MainPID")
	if err != nil {
		return "", "", err
	}
	state, pid := "", ""
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && k == "ActiveState" {
			state = v
		}
		if ok && k == "MainPID" {
			pid = v
		}
	}
	if state == "inactive" || state == "failed" {
		if pid != "0" {
			return "", "", errors.New("Apache 停止状态与主进程矛盾")
		}
		return state, "", nil
	}
	number, err := strconv.Atoi(pid)
	if state != "active" || err != nil || number <= 1 {
		return "", "", errors.New("Apache 原生进程状态未能核实")
	}
	binary, err := os.Readlink(filepath.Join("/proc", pid, "exe"))
	if err != nil {
		return "", "", err
	}
	for _, r := range runtimecatalog.Apache {
		if r.CLI() == binary {
			return state, r.ID, nil
		}
	}
	return "", "", errors.New("Apache 主进程未使用受管审核程序")
}

func (s *Service) apacheRuntimeReloadOrRestart(ctx context.Context, release runtimecatalog.Release) error {
	state, running, err := s.apacheRunningRelease(ctx)
	if err != nil {
		return err
	}
	if state != "active" {
		return errors.New("Apache 共享服务未运行，未隐式启动")
	}
	operation := "reload"
	if running != release.ID {
		operation = "restart"
	}
	_, err = s.Config.Run(ctx, "/usr/bin/systemctl", operation, "panel-apache")
	return err
}

func apacheRuntimeProbeStatuses(ctx context.Context, sites []core.Site) (map[string]int, error) {
	if len(sites) > 4096 {
		return nil, errors.New("Apache 站点清单超限")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	out := map[string]int{}
	for _, site := range sites {
		if core.DefaultSiteSettings(site.Settings).WebServer != "apache" || site.Status == "stopped" {
			continue
		}
		if !core.ValidID(site.ID) || !core.ValidDomain(site.Domain) || site.Status != "running" {
			return nil, errors.New("Apache 站点未完成或身份异常")
		}
		for _, domain := range append([]string{site.Domain}, site.Settings.Domains...) {
			if !core.ValidDomain(domain) {
				return nil, errors.New("Apache 域名身份异常")
			}
			if len(out) >= 128 {
				return nil, errors.New("Apache 原生入口验收域名超过 128 个")
			}
			request, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19080/", nil)
			request.Host = domain
			response, err := client.Do(request)
			if err != nil {
				return nil, err
			}
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 256<<10))
			response.Body.Close()
			if readErr != nil || response.StatusCode >= 500 {
				return nil, errors.New("Apache 原生站点未通过有界入口检查")
			}
			out[domain] = response.StatusCode
		}
	}
	if len(out) == 0 {
		return nil, errors.New("没有运行中的 Apache 站点，未改变共享服务状态")
	}
	return out, nil
}

func (s *Service) switchApacheRuntime(ctx context.Context, request core.ApacheRuntimeDispatch, sites []core.Site) (result core.ApplyResult, err error) {
	result = core.ApplyResult{Status: "unchanged", Steps: []core.Step{}}
	if os.Geteuid() != 0 || s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || !core.ValidID(request.JobID) || !core.ValidID(request.ActorID) || request.AccessRevision < 1 || request.ReleaseID != runtimecatalog.ApacheCurrentID || request.EngineJobID != "" && !core.ValidID(request.EngineJobID) {
		return result, errors.New("Apache 切换只允许真实受管环境与当前完整原请求")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	unlock, err := s.lockRuntimeUse()
	if err != nil {
		return result, err
	}
	defer unlock()
	txs := s.apacheWAFTransactionService()
	lock, err := txs.lockWAFConfiguration()
	if err != nil {
		return result, err
	}
	defer lock.Close()
	if op, readErr := readApacheRuntimeOperation(request.JobID); readErr == nil {
		if op.Request != request {
			return result, errors.New("Apache 原任务被用于不同请求，未执行")
		}
		if op.State == "committed" {
			return op.Result, nil
		}
		return op.Result, errors.New("Apache 原任务未提交或已失败，原证据保留；读取原结果不会重启或重做")
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return result, readErr
	}
	if err := txs.recoverApacheWAFBeforeMutation(ctx); err != nil {
		return result, err
	}
	previous, err := apacheRelease()
	if err != nil {
		return result, err
	}
	next, _ := runtimecatalog.Find(request.ReleaseID)
	if previous.ID == next.ID {
		state, running, err := s.apacheRunningRelease(ctx)
		if err != nil || state != "active" || running != next.ID {
			return result, errors.New("Apache 配置已选择目标但实际进程未使用目标程序；未冒充切换完成")
		}
		if _, err := LoadRuntime(next.ID); err != nil {
			return result, err
		}
		return core.ApplyResult{Status: "unchanged", Steps: []core.Step{{Time: core.Now(), Message: "Apache 配置及实际进程已使用目标版本，未重复重启"}}}, nil
	}
	if previous.ID != runtimecatalog.ApacheLegacyID {
		return result, errors.New("Apache 原运行版本不是本次审核的兼容升级来源")
	}
	if _, err := LoadRuntime(next.ID); err != nil {
		return result, err
	}
	if err := verifyRuntimeVersion(ctx, next); err != nil {
		return result, err
	}
	state, running, err := s.apacheRunningRelease(ctx)
	if err != nil || state != "active" || running != previous.ID {
		return result, errors.New("Apache 原配置与原生运行程序不一致，未切换")
	}
	source, err := apacheWAFReadStableFile(s.Config.ApacheSiteConfig, 2<<20)
	if err != nil {
		return result, err
	}
	bindings, err := apacheWAFBindings(string(source))
	if err != nil {
		return result, err
	}
	requested := map[string][]string{}
	for _, site := range sites {
		if site.Status != "stopped" && core.DefaultSiteSettings(site.Settings).WebServer == "apache" {
			if _, duplicate := requested[site.ID]; duplicate {
				return result, errors.New("Apache 网站身份重复")
			}
			requested[site.ID] = append([]string{site.Domain}, site.Settings.Domains...)
		}
	}
	if len(requested) != len(bindings) {
		return result, errors.New("Apache 实际配置与完整网站清单不一致")
	}
	for id, domains := range bindings {
		actual, exists := requested[id]
		if !exists || len(actual) != len(domains) {
			return result, errors.New("Apache 原配置含未确认的站点或域名")
		}
		for i := range domains {
			if domains[i] != actual[i] {
				return result, errors.New("Apache 原配置域名与网站记录不一致")
			}
		}
	}
	before, err := apacheRuntimeProbeStatuses(ctx, sites)
	if err != nil {
		return result, err
	}
	plan, err := s.planApacheRuntimeSwitch(ctx, previous, next, request.EngineJobID)
	if err != nil {
		return result, err
	}
	if err := ensureApacheBodyDirectory(apacheRuntimeOperations, 0700); err != nil {
		return result, err
	}
	entries, err := os.ReadDir(apacheRuntimeOperations)
	if err != nil || len(entries) >= 128 {
		return result, errors.New("Apache 运行任务保留达到 128 份，未删除历史")
	}
	op := apacheRuntimeOperation{Request: request, State: "planning", Result: result}
	if err := saveApacheRuntimeOperation(op, true); err != nil {
		return result, err
	}
	defer func() {
		op.Result = result
		if err != nil {
			op.State = "failed"
			op.Error = err.Error()
		} else {
			op.State = "committed"
		}
		err = errors.Join(err, saveApacheRuntimeOperation(op, false))
	}()
	owner, err := currentModuleApplyOwner()
	if err != nil {
		return result, err
	}
	tx, err := txs.startWAFTransaction(plan.Changes)
	if err != nil {
		return result, err
	}
	bootID, err := s.apacheRuntimeBootID()
	if err != nil {
		return result, err
	}
	tx.ApacheRuntime = &apacheRuntimeTransition{JobID: request.JobID, PreviousID: previous.ID, NextID: next.ID, ApplyOwner: owner, BootID: bootID}
	if err := txs.wafTransactionContract(tx); err != nil {
		return result, err
	}
	if err := wafWriteTransaction(txs.wafPendingPath(), tx); err != nil {
		return result, err
	}
	result.Status = "needs_attention"
	op.State = "applying"
	op.TransactionID = tx.ID
	if err := saveApacheRuntimeOperation(op, false); err != nil {
		return result, err
	}
	rollback := func(cause error) error {
		bounded, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		restoreErr := txs.recoverApacheWAFBeforeMutation(bounded)
		if restoreErr == nil {
			actualState, actualID, probeErr := s.apacheRunningRelease(bounded)
			if probeErr != nil || actualState != "active" || actualID != previous.ID {
				restoreErr = errors.New("Apache 恢复后原程序运行身份未确认")
			}
		}
		if restoreErr == nil {
			result.Status = "restored"
		}
		return fmt.Errorf("Apache 新版本未提交，原程序和完整配置恢复核对=%v；证据保留：%w", restoreErr == nil, errors.Join(cause, restoreErr))
	}
	for _, change := range tx.Changes {
		if err := ctx.Err(); err != nil {
			return result, rollback(err)
		}
		same, err := txs.wafCurrentMatches(change, false)
		if err != nil || !same {
			return result, rollback(errors.New("Apache 配置在切换期间被外部修改"))
		}
		if err := wafApplyChange(change, true); err != nil {
			return result, rollback(err)
		}
	}
	if _, err := s.Config.Run(ctx, next.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); err != nil {
		return result, rollback(err)
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "panel-apache"); err != nil {
		return result, rollback(err)
	}
	afterState, afterID, err := s.apacheRunningRelease(ctx)
	if err != nil || afterState != "active" || afterID != next.ID {
		return result, rollback(errors.New("Apache 新主进程未使用目标可执行程序"))
	}
	after, err := apacheRuntimeProbeStatuses(ctx, sites)
	if err != nil {
		return result, rollback(err)
	}
	if len(before) != len(after) {
		return result, rollback(errors.New("Apache 原域名清单变化"))
	}
	for domain, status := range before {
		if after[domain] != status {
			return result, rollback(errors.New("Apache 原域名响应状态变化"))
		}
	}
	if plan.WAFVersion != "" {
		if err := s.verifyApacheBodyTransition(ctx, plan.Next, plan.Next); err != nil {
			return result, rollback(err)
		}
		domain, err := apacheWAFConfigurationFilesMatchVersion(string(plan.Changes[0].NextData), plan.Next, filepath.Join(next.Prefix(), "modules/mod_remoteip.so"), plan.Changes[1].Path, plan.WAFVersion)
		if err != nil {
			return result, rollback(err)
		}
		if err := apacheWAFWaitLoadedVersion(ctx, plan.Next, domain, plan.WAFVersion); err != nil {
			return result, rollback(err)
		}
	}
	for _, change := range tx.Changes {
		same, err := txs.wafCurrentMatches(change, true)
		if err != nil || !same {
			return result, rollback(errors.New("Apache 新配置与完整回执不一致"))
		}
	}
	tx.State = "committed"
	if err := txs.finishWAFTransaction(tx); err != nil {
		return result, fmt.Errorf("Apache 新程序已核对，但恢复事务未确认归档，原证据保留：%w", err)
	}
	result.Status = "running"
	result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: fmt.Sprintf("Apache %s → %s；新可执行程序、%d 个原生域名与完整防护策略已核对，原程序、站点数据和配置备份保留", previous.Version, next.Version, len(after))})
	return result, nil
}

func (s *Service) apacheRuntimeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/apache/runtime/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !core.ValidID(id) {
			respond(w, 400, map[string]string{"error": "Apache 原任务标识无效"})
			return
		}
		if !s.mu.TryLock() {
			respond(w, 200, map[string]any{"job_id": id, "state": "busy"})
			return
		}
		defer s.mu.Unlock()
		op, err := readApacheRuntimeOperation(id)
		if errors.Is(err, os.ErrNotExist) {
			respond(w, 200, map[string]any{"job_id": id, "state": "missing"})
			return
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		originalState := op.State
		txs := s.apacheWAFTransactionService()
		lease, err := txs.lockWAFObservation()
		if err != nil {
			respond(w, 200, map[string]any{"job_id": id, "state": "busy"})
			return
		}
		defer lease.Close()
		if derived, err := s.observeApacheRuntimeRecovery(r.Context(), op); err == nil {
			op = derived
		}
		respond(w, 200, map[string]any{"job_id": id, "state": op.State, "original_state": originalState, "request": op.Request, "result": op.Result, "error": op.Error})
	})
	m.HandleFunc("GET /v1/apache/runtime", func(w http.ResponseWriter, r *http.Request) {
		selected, err := apacheRelease()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		state, running, err := s.apacheRunningRelease(r.Context())
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		engineRequired := false
		wafVersion := ""
		installed, recordErr := s.moduleInstalledRecord("apache-waf")
		if recordErr == nil {
			version, ok := installed["version"].(string)
			settings, settingsOK := installed["settings"].(map[string]any)
			if !ok || !settingsOK {
				respond(w, 409, map[string]string{"error": "Apache 防护原安装记录不完整"})
				return
			}
			cfg, err := core.DecodeApacheWAFVersionConfig(settings, version)
			if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
			engineRequired = apacheBodyActive(cfg) || cfg.ApacheCC != nil
			wafVersion = version
		} else if !errors.Is(recordErr, os.ErrNotExist) {
			respond(w, 409, map[string]string{"error": recordErr.Error()})
			return
		}
		_, targetErr := LoadRuntime(runtimecatalog.ApacheCurrentID)
		respond(w, 200, map[string]any{"selected_id": selected.ID, "running_id": running, "service_state": state, "recommended_id": runtimecatalog.ApacheCurrentID, "target_installed": targetErr == nil, "native_engine_required": engineRequired, "waf_version": wafVersion, "activation_needed": selected.ID != runtimecatalog.ApacheCurrentID || running != selected.ID || targetErr != nil, "checked_at": core.Now()})
	})
	m.HandleFunc("POST /v1/apache/runtime/switch", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Request core.ApacheRuntimeDispatch `json:"request"`
			Sites   []core.Site                `json:"sites"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		result, err := s.switchApacheRuntime(r.Context(), in.Request, in.Sites)
		if err != nil {
			respond(w, 409, map[string]any{"error": err.Error(), "steps": result.Steps})
			return
		}
		respond(w, 200, result)
	})
}

// Observe a cold startup's original journal outcome without recovering it again,
// rewriting the old operation record, starting a service or recreating a job.
func (s *Service) observeApacheRuntimeRecovery(ctx context.Context, op apacheRuntimeOperation) (apacheRuntimeOperation, error) {
	if op.State != "planning" && op.State != "applying" && !(op.State == "failed" && op.Result.Status == "needs_attention") {
		return op, nil
	}
	txs := s.apacheWAFTransactionService()
	if _, err := os.Lstat(txs.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return op, errors.New("Apache 原事务仍待恢复确认，未把观察当成完成")
	}
	if op.TransactionID == "" && op.State == "planning" {
		op.State = "failed"
		op.Result.Status = "unchanged"
		op.Error = "Apache 在写入配置前中断；未重新执行原切换"
		return op, nil
	}
	if !core.ValidID(op.TransactionID) {
		return op, errors.New("Apache 原事务标识缺失")
	}
	tx, err := txs.readWAFTransactionFile(filepath.Join(filepath.Dir(txs.wafPendingPath()), op.TransactionID+".json"))
	if err != nil {
		return op, err
	}
	if tx.ID != op.TransactionID || tx.ApacheRuntime == nil || tx.ApacheRuntime.JobID != op.Request.JobID || tx.ApacheRuntime.NextID != op.Request.ReleaseID || tx.State != "recovered" && tx.State != "committed" {
		return op, errors.New("Apache 原事务尚无对应完整终态")
	}
	next := tx.State == "committed"
	for _, change := range tx.Changes {
		same, err := txs.wafCurrentMatches(change, next)
		if err != nil || !same {
			return op, errors.New("Apache 原事务终态的配置、UID/GID 或摘要已变化")
		}
	}
	expected := tx.ApacheRuntime.PreviousID
	if next {
		expected = tx.ApacheRuntime.NextID
	}
	selected, err := apacheRelease()
	if err != nil || selected.ID != expected {
		return op, errors.New("Apache 终态配置选择与原事务不一致")
	}
	state, running, err := s.apacheRunningRelease(ctx)
	if err != nil || state != "active" || running != expected {
		return op, errors.New("Apache 原事务终态没有对应的实际运行程序")
	}
	installed, err := s.moduleInstalledRecord("apache-waf")
	if err == nil {
		version, ok := installed["version"].(string)
		settings, settingsOK := installed["settings"].(map[string]any)
		if !ok || !settingsOK {
			return op, errors.New("Apache 原防护安装记录缺失")
		}
		if err := s.verifyApacheWAFHealth(ctx, version, settings); err != nil {
			return op, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return op, err
	} else if err := s.apacheBodyNoOrphanSource(); err != nil {
		return op, err
	}
	if next {
		op.State = "committed"
		op.Error = ""
		op.Result.Status = "running"
		op.Result.Steps = append(op.Result.Steps, core.Step{Time: core.Now(), Message: "只读核对原已提交事务及冷启动后的目标程序，未重新切换或重启"})
	} else {
		op.State = "failed"
		op.Result.Status = "restored"
		op.Error = "原中断切换已经由启动恢复保留原程序与完整配置；仅核对原结果，没有重新执行"
	}
	return op, nil
}
