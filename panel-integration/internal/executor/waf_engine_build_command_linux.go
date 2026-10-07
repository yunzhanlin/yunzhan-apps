//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Caller supplies only commands returned by the internal fixed build plan.
// This helper is not an API and never accepts panel/plugin command strings.
// A dedicated bounded systemd unit supplies memory/PID/CPU constraints; this
// runner supplies cancellation of the process group and a capped private log.
func runWAFNativeBuildCommand(ctx context.Context, command wafBuildCommand, logPath, buildHome string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateWAFBuildCommand(command); err != nil {
		return err
	}
	if !wafEngineConfigPath(buildHome) || !wafEngineConfigPath(logPath) {
		return errors.New("WAF 构建日志或专用主目录无效")
	}
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	st, err := log.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return errors.New("WAF 构建日志不是私有普通文件")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("WAF 构建日志所有者或链接数异常")
	}
	const limit = 64 << 20
	if st.Size() >= limit {
		return errors.New("WAF 构建日志已达 64 MiB，保留日志并停止构建")
	}
	arguments := append([]string{"-u", "panel-build", "--", command.Program}, command.Arguments...)
	cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", arguments...)
	cmd.Dir = command.Directory
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + buildHome, "LANG=C", "LC_ALL=C", "CFLAGS=-O2 -g0", "CXXFLAGS=-O2 -g0", "MAKEFLAGS="}, command.Environment...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 3 * time.Second
	out := &boundedBuffer{max: 24 << 10}
	cmd.Stdout = io.MultiWriter(&cappedLog{File: log, Remaining: limit - st.Size()}, out)
	cmd.Stderr = cmd.Stdout
	if err := cmd.Run(); err != nil {
		// Raw compiler output stays in the private build log, never a public
		// event/Webhook or a caller-controlled executable invocation.
		return fmt.Errorf("%s 未完成: %w；专用构建日志保留于 %s", command.Label, err, logPath)
	}
	if after, err := log.Stat(); err != nil || after.Size() >= limit {
		return errors.New("WAF 构建日志达到 64 MiB 上限，拒绝发布部分日志的构建结果")
	}
	return log.Sync()
}
