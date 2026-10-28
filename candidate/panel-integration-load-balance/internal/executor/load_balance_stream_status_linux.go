//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Native installation status has a separate read-only authority path. The
// generic module reader must keep refusing a native record: accepting its
// version/installation_id there would also open legacy lifecycle consumers.
// Configured private roots never redirect the fixed native host readers.
func (s *Service) loadBalanceStreamAppStatus(ctx context.Context) (core.SoftwareAppStatus, bool) {
	if s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" {
		return core.SoftwareAppStatus{}, false
	}
	module, err := s.moduleRecordDirectory("load-balance")
	if err != nil {
		return core.SoftwareAppStatus{}, false
	}
	defer module.Close()
	record, err := holdLoadBalanceStreamModuleAt(module.Root, module.current)
	if err != nil {
		return core.SoftwareAppStatus{}, false
	}
	defer record.close()
	if record.missing {
		return core.SoftwareAppStatus{}, false
	}
	manifest, err := decodeLoadBalanceStreamModule(record.raw)
	if err != nil || manifest["version"] != loadbalancestream.AppVersion {
		return core.SoftwareAppStatus{}, false
	}
	out := core.SoftwareAppStatus{ID: "load-balance", StateUnknown: true,
		Detail: "原生安装的完整回执或当前状态无法核对；未将版本号当作安装成功"}
	if ctx == nil || ctx.Err() != nil {
		return out, true
	}
	installed, err := holdLoadBalanceStreamInstalledContext(ctx)
	if err != nil {
		return out, true
	}
	defer installed.close()
	if !bytes.Equal(record.raw, installed.installed.raw) {
		return out, true
	}
	workspace, err := observeLoadBalanceStreamWorkspace(ctx)
	if err != nil || core.ValidateLoadBalanceStreamWorkspace(workspace) != nil || !workspace.Available ||
		installed.current(ctx) != nil || !record.current() {
		return out, true
	}
	out.StateUnknown, out.Installed, out.Enabled = false, true, true
	out.Version, out.InstallationID = loadbalancestream.AppVersion, installed.receipt.InstallationID
	out.Settings, _ = manifest["settings"].(map[string]any)
	out.Detail = workspace.Detail
	// An empty, fully proven installation is ready without creating listeners.
	// Busy/degraded/unknown traffic state does not erase the proven installation
	// or invite reinstall; it remains explicitly unhealthy. Backend reachability
	// and public ingress are never inferred from configuration receipts.
	switch workspace.State {
	case "empty", "running", "stopped":
		out.Healthy = true
	}
	if _, err := os.Lstat(s.loadBalancePendingPath()); !errors.Is(err, os.ErrNotExist) {
		out.Healthy = false
		out.Detail = "存在待恢复 HTTP/HTTPS 入口事务；原生安装已核对，但未宣称全部入口配置生效"
	}
	return out, true
}
