//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamWorkspace = core.LoadBalanceStreamWorkspace

// No installation, journal initialization, account creation, grant, business
// request, replay or recovery occurs in this reader. Configuration validity
// is explicitly separate from backend/business health and public ingress.
func observeLoadBalanceStreamWorkspace(ctx context.Context) (loadBalanceStreamWorkspace, error) {
	out := loadBalanceStreamWorkspace{Format: 1, Version: loadbalancestream.AppVersion, State: "unavailable",
		BindAddress: "127.0.0.1", Entries: []loadbalancestream.Entry{},
		Detail: "TCP/UDP 独立控制器尚未完成发布与实装验收；现有 HTTP/HTTPS 入口不变"}
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || !loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return out, errLoadBalanceStreamInstallationGate
	}
	installed, err := holdLoadBalanceStreamInstalledContext(ctx)
	if err != nil {
		return out, nil
	}
	defer installed.close()
	out.Available, out.State = true, "unknown"
	source, err := openLoadBalanceStreamCoreAuthority(ctx)
	if err != nil {
		return out, err
	}
	defer source.close()
	history, err := source.controlUpgradeHistory(ctx, nil)
	if err != nil {
		out.State, out.Detail = "busy-or-unknown", "存在正在变更或尚需核对的原事务；未把旧缓存作为当前状态"
		return out, nil
	}
	closed := 0
	for _, row := range history {
		if row.State == "completed" && row.ResultState == "committed" {
			closed++
		}
	}
	if closed == 0 {
		for _, path := range []string{loadBalanceStreamStateRoot, loadBalanceStreamConfigurationRoot,
			loadBalanceStreamConfigurationPublicationsRoot, loadBalanceStreamGenerationPublicationsRoot} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				out.Detail = "发现无法对应原完成事务的原生状态；未采用或修复"
				return out, nil
			}
		}
		if _, err := os.Lstat(loadBalanceStreamJobsRoot); err == nil {
			jobs, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamJobsRoot, false)
			if err != nil {
				return out, err
			}
			valid := streamConfigurationExactDirectories(jobs, map[string]bool{}) == nil
			jobs.Close()
			if !valid {
				return out, loadbalancestream.ErrJournal
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
		state, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
		if err != nil || state["LoadState"] != "not-found" || state["MainPID"] != "0" || state["ControlPID"] != "0" {
			return out, loadbalancestream.ErrService
		}
		out.State, out.Detail = "empty", "原生控制器已安装，尚无 TCP/UDP 入口；不会自动创建监听"
		return out, nil
	}
	generation, err := holdLoadBalanceStreamRecordedGeneration(ctx, installed, source)
	if err != nil {
		out.Detail = "当前原始代次或完整完成链需要核对"
		return out, nil
	}
	defer generation.close()
	seedRaw, _, _, err := generation.journal.original(ctx)
	if err != nil {
		return out, err
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil {
		return out, err
	}
	pool, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamConfigurationPublicationsRoot, false)
	if err != nil {
		return out, err
	}
	defer pool.Close()
	pub, err := pool.OpenRoot(generation.value.RequestID)
	if err != nil {
		return out, err
	}
	defer pub.Close()
	cfg, err := os.OpenRoot(loadBalanceStreamConfigurationRoot)
	if err != nil {
		return out, err
	}
	defer cfg.Close()
	h, err := checkStreamConfigurationPublication(pub, cfg, seedRaw, installed.identity.GID, true)
	if err != nil || len(h.ServiceReceipt) == 0 || len(h.CompletionReceipt) == 0 ||
		core.Hash(string(h.ServiceReceipt)) != generation.value.ServiceObservationSHA256 {
		out.Detail = "实际当前配置或完整原生回执需要核对"
		return out, nil
	}
	receipt, err := decodeStreamServiceReceipt(h.ServiceReceipt, seedRaw)
	if err != nil || receipt.InstallationID != installed.receipt.InstallationID {
		return out, loadbalancestream.ErrService
	}
	completion, err := decodeStreamControlCompletion(h.CompletionReceipt, seedRaw)
	if err != nil || completion.Generation != generation.value.Generation || completion.GenerationSHA256 != core.Hash(string(generation.raw)) || core.Hash(completion.Records[len(completion.Records)-1]) != generation.value.FinalEventSHA256 {
		return out, loadbalancestream.ErrJournal
	}
	facts, err := measureLoadBalanceStreamServiceFacts(ctx, installed)
	if err != nil {
		return out, err
	}
	ports, err := observeLoadBalanceStreamControlPorts(ctx)
	if err != nil {
		return out, err
	}
	facts.Validation.PanelControlPorts = ports
	plan, err := loadbalancestream.RecordedControlServicePlan(seed, facts)
	if err != nil || plan.SHA256 != generation.value.ServiceUnitSHA256 {
		return out, loadbalancestream.ErrService
	}
	out.Generation, out.RequestID, out.ConfigurationSHA256, out.Entries = generation.value.Generation, generation.value.RequestID, generation.value.ConfigurationSHA256, generation.value.Entries
	out.AvailableMemoryBytes, out.MemoryHighBytes, out.MemoryMaxBytes = facts.AvailableMemoryBytes, plan.MemoryHighBytes, plan.MemoryMaxBytes
	egress, err := holdLoadBalanceStreamRecordedEgress(ctx, seed, receipt.State, installed.identity.UID, receipt.Egress)
	if err != nil {
		if streamColdBootWorkspaceCurrent(ctx, installed, generation, receipt.Egress.BootID) == nil {
			out.State, out.Detail = "cold-boot-ready", "服务器已重启；原生服务未运行，专用身份没有存活进程，隔离表尚未恢复。提交新配置后将恢复原有未移除入口并应用本次变更；不会重放旧请求"
			return out, nil
		}
		out.State, out.Detail = "degraded", "当前防火墙完整规则、原始句柄或启动身份与回执不一致；未验证为运行正常"
		return out, nil
	}
	defer egress.close()
	if receipt.State == "stopped" {
		var stopped streamServiceRecordedStopped
		if json.Unmarshal(receipt.Native, &stopped) != nil || plan.ShouldRun || !streamManagedServiceInactive(ctx, stopped.InvocationID) || egress.current(ctx) != nil {
			out.Detail = "原停止记录与实际服务状态不一致"
			return out, nil
		}
		out.State, out.ConfigurationVerified, out.Detail = "stopped", true, "原停止回执与当前未运行状态一致；未启动或恢复旧请求"
		return out, nil
	}
	live, err := observeLoadBalanceStreamService(ctx, installed, plan, true)
	if err != nil {
		out.State, out.Detail = "degraded", "服务、进程身份、资源或过滤策略需要核对"
		return out, nil
	}
	defer live.close()
	if !streamServiceMatchesRecorded(live, receipt) || verifyLoadBalanceStreamConfigurationMarkers(ctx, live, seed.After) != nil || generation.current(ctx) != nil || egress.current(ctx) != nil {
		out.State, out.Detail = "degraded", "当前工作进程、完整配置标记或原始代次不一致；不推断为业务健康"
		return out, nil
	}
	out.State, out.ConfigurationVerified, out.RetiringWorkers = "running", true, len(live.Processes)-2
	out.Detail = "实际专用进程、配置与监听标记一致；仅回环入口，不代表公网可达或后端业务健康"
	return out, nil
}
