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
// Each compiler uses its own closed dedicated cgroup and retained stable PID
// references. Sharing collection never aliases their source or unit authority.
func runWAFNativeBuildCommand(ctx context.Context, command wafBuildCommand, logPath, buildHome string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateWAFBuildCommand(command); err != nil {
		return err
	}
	return runBoundedNativeBuildCommand(ctx, command, logPath, buildHome, false)
}

func runApacheBodyNativeBuildCommand(ctx context.Context, paths apacheBodyBuildPaths, index int, command wafBuildCommand, logPath, buildHome string) error {
	if err := validateApacheBodyBuildCommand(paths, index, command); err != nil {
		return err
	}
	return runBoundedNativeBuildCommand(ctx, command, logPath, buildHome, true)
}

// Source-specific validators above remain separate. Sharing cancellation and
// log bounds does not expand Nginx's command or download source authority.
func runBoundedNativeBuildCommand(ctx context.Context, command wafBuildCommand, logPath, buildHome string, clearInherited bool) error {
	authority := nativeNginxWAFCompilerAuthority
	if clearInherited {
		authority = nativeApacheCompilerAuthority
	}
	return runScopedNativeBuildCommand(ctx, command, logPath, buildHome, authority)
}

func runAnalyticsHTMLNativeBuildCommand(ctx context.Context, command wafBuildCommand, logPath, buildHome string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateWAFBuildCommand(command); err != nil {
		return err
	}
	return runScopedNativeBuildCommand(ctx, command, logPath, buildHome, nativeAnalyticsHTMLCompilerAuthority)
}

// The internal authority is selected only by the compiled source-specific
// entrypoints above. It is never an API or plugin field.
func runScopedNativeBuildCommand(ctx context.Context, command wafBuildCommand, logPath, buildHome string, authority nativeCompilerAuthority) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !wafEngineConfigPath(buildHome) || !wafEngineConfigPath(logPath) {
		return errors.New("WAF 构建日志或专用主目录无效")
	}
	if authority != nativeApacheCompilerAuthority && authority != nativeNginxWAFCompilerAuthority && authority != nativeAnalyticsHTMLCompilerAuthority {
		return errors.New("未知请求体或 HTML 编译授权，未执行")
	}
	scope, scopeErr := beginNativeCompilerScope(authority)
	if scopeErr != nil {
		return scopeErr
	} // Before log creation or source execution.
	defer scope.Close()
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
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
	// Every source compiler explicitly clears active/inherited capabilities.
	arguments := runtimeBuildIdentityArgs(command.Program, command.Arguments...)
	cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", arguments...)
	cmd.Dir = command.Directory
	cmd.Env = nativeBuildEnvironment(buildHome, command.Environment, authority == nativeApacheCompilerAuthority)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		_, err := scope.signalMembers()
		return err
	}
	cmd.WaitDelay = 3 * time.Second
	out := &boundedBuffer{max: 24 << 10}
	cmd.Stdout = io.MultiWriter(&cappedLog{File: log, Remaining: limit - st.Size()}, out)
	cmd.Stderr = cmd.Stdout
	runErr := cmd.Run()
	leftovers, collectErr := scope.collect()
	if leftovers && runErr == nil {
		runErr = errors.New("请求体编译命令留下后台子进程，已回收且拒绝发布程序")
	}
	runErr = errors.Join(runErr, collectErr, ctx.Err(), scope.writeCollectionDiagnostics(log))
	runErr = errors.Join(runErr, log.Sync())
	if runErr != nil {
		// Raw compiler output stays in the private build log, never a public
		// event/Webhook or a caller-controlled executable invocation.
		return fmt.Errorf("%s 未完成: %w；专用构建日志保留于 %s", command.Label, runErr, logPath)
	}
	if after, err := log.Stat(); err != nil || after.Size() >= limit {
		return errors.New("WAF 构建日志达到 64 MiB 上限，拒绝发布部分日志的构建结果")
	}
	return log.Sync()
}

func nativeBuildEnvironment(buildHome string, overrides []string, apache bool) []string {
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + buildHome, "LANG=C", "LC_ALL=C", "CFLAGS=-O2 -g0", "CXXFLAGS=-O2 -g0", "MAKEFLAGS="}
	if apache {
		// These are fixed author-reviewed flags, not inherited shell settings
		// or a panel/plugin option. Leave Nginx's existing environment intact.
		env[4] = "CFLAGS=-O2 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-common"
		env[5] = "CXXFLAGS=-O2 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-common"
		env = append(env, "LDFLAGS=-Wl,-z,relro,-z,now")
	}
	return append(env, overrides...)
}
