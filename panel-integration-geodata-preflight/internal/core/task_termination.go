package core

import (
	"context"
	"errors"
	"fmt"
)

func taskSignalReplyMatches(value map[string]any, pid int) bool {
	return len(value) == 4 && value["signal"] == "SIGTERM" && value["pid"] == float64(pid) && value["signal_accepted"] == true && value["exit_verified"] == false
}

// A request audit must be durable before the irreversible RPC. A lost reply or
// a failed result audit cannot certify signal delivery, exit or safe retry.
func (a *Server) terminateAppTask(ctx context.Context, u identity, in AppModuleInput) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if in.PID < 2 || in.PID > 2147483647 || in.StartTime == 0 {
		return nil, errors.New("请选择当前进程列表中的完整原进程身份")
	}
	access, err := a.Store.UserAccess(u.ID)
	if err != nil || access.Role != "admin" || !containsMenu(access.MenuIDs, ModuleMenu("task-manager")) {
		return nil, errors.New("当前账户不再具有受管进程操作授权，未发送信号")
	}
	target := fmt.Sprintf("pid:%d:start:%d", in.PID, in.StartTime)
	if err := a.Store.Audit(u.Username, "app-module.terminate.requested", target, "SIGTERM requested; exit unverified"); err != nil {
		return nil, errors.New("原进程信号请求审计无法保存，未发送信号")
	}
	var out map[string]any
	err = a.Executor.Call(ctx, "POST", "/v1/app-modules/task-manager/terminate", in, &out)
	if err != nil || !taskSignalReplyMatches(out, in.PID) {
		_ = a.Store.Audit(u.Username, "app-module.terminate.unknown", target, "signal outcome unknown; no automatic retry")
		return nil, errors.New("原进程信号结果不可完整核对；可能已经发送，请刷新实际状态，不自动重发或宣称退出")
	}
	if err := a.Store.Audit(u.Username, "app-module.terminate", target, "SIGTERM accepted; exit unverified"); err != nil {
		return nil, errors.New("SIGTERM 可能已发送，但结果审计无法保存；请刷新实际状态，不自动重发或宣称退出")
	}
	return out, nil
}
