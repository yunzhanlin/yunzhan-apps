//go:build linux

package executor

import (
	"context"
	"os"
	"time"

	"local/panel/internal/core"
)

// Fixed original-unit worker, not a general user-management or recovery API.
// Only the strict dependency CLI entry is wired, never a network RPC. Its sole
// argument is the selected original job ID;
// no account, UID/GID, path, programme key, shell or alternate runner is accepted.
func RunLoadBalanceStreamAccountJob(job string) error {
	if os.Getuid() != 0 || os.Getgid() != 0 || os.Geteuid() != 0 || os.Getegid() != 0 || !core.ValidID(job) ||
		!loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return errLoadBalanceStreamAccount
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	record, err := readLoadBalanceStreamAccountPermit(job)
	if err != nil {
		return streamInstallPhaseError("专用身份原始父进程凭据", err)
	}
	defer record.close()
	if !record.current() || !loadBalanceStreamProgrammeInputsMatch(loadBalanceStreamCompiledProgrammeInputsSHA256, record.value.ProgrammeInputsSHA256) {
		return streamInstallPhaseError("专用身份凭据与构建核对", errLoadBalanceStreamAccount)
	}
	j, err := openLoadBalanceStreamInstallationJournalReadOnlyAt(loadBalanceStreamInstallationJobsRoot, job)
	if err != nil {
		return streamInstallPhaseError("专用身份原始安装记录", err)
	}
	defer j.close()
	parent, err := holdLoadBalanceStreamAccountParent(ctx, record.value, j)
	if err != nil {
		return streamInstallPhaseError("专用身份实际父进程", err)
	}
	defer parent.Close()
	parent.permitRecord = record
	if !record.current() || checkLoadBalanceStreamAccountChildKernel(ctx, parent) != nil {
		return streamInstallPhaseError("专用身份实际子进程", errLoadBalanceStreamAccount)
	}
	if _, err := prepareLoadBalanceStreamSystemAccount(ctx, parent); err != nil {
		return streamInstallPhaseError("专用身份独立创建协议", err)
	}
	if !record.current() || parent.current(ctx) != nil || ctx.Err() != nil {
		return errLoadBalanceStreamAccount
	}
	return nil
}
