//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/geodata"
	"local/panel/internal/upgradeguard"
)

const statisticsGeoVerifyPrefix = "panel-geodata-verify-"
const statisticsGeoVerifyUnit = statisticsGeoVerifyPrefix + "cache.service"

func statisticsGeoVerifyState(raw string) (map[string]string, error) {
	out := map[string]string{}
	if len(raw) > 2048 {
		return nil, errors.New("地域核对单元状态超限")
	}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "Environment" && key != "LoadState" && key != "ActiveState" && key != "SubState" {
			return nil, errors.New("地域核对单元状态字段未知")
		}
		if _, found := out[key]; found {
			return nil, errors.New("地域核对单元状态重复")
		}
		out[key] = value
	}
	if len(out) != 4 {
		return nil, errors.New("地域核对单元状态不完整")
	}
	return out, nil
}

func statisticsGeoVerifyOwned(raw, token string) bool {
	state, err := statisticsGeoVerifyState(raw)
	if err != nil || !core.ValidID(token) || state["LoadState"] != "loaded" {
		return false
	}
	fields := strings.Fields(state["Environment"])
	return len(fields) == 2 && (fields[0] == "GOMEMLIMIT=512MiB" && fields[1] == "PANEL_GEODATA_VERIFY_TOKEN="+token || fields[1] == "GOMEMLIMIT=512MiB" && fields[0] == "PANEL_GEODATA_VERIFY_TOKEN="+token)
}

// Only the actual installed running executable can supply the verifier.
// A caller cannot set a binary path, unit name, key or resource limit.
func statisticsGeoVerifierProgram() (string, error) {
	name, err := os.Executable()
	if err != nil {
		return "", err
	}
	name, err = filepath.EvalSymlinks(name)
	if err != nil || name != "/opt/panel/bin/panel-executor" && !(strings.HasPrefix(name, "/opt/panel/releases/") && strings.HasSuffix(name, "/bin/panel-executor")) {
		return "", errors.New("地域核对器不是固定受信面板程序")
	}
	if statisticsGeoParents(filepath.Dir(name)) != nil {
		return "", errors.New("地域核对程序父目录不受信")
	}
	info, err := os.Lstat(name)
	self, selfErr := os.Stat("/proc/self/exe")
	owner, ok := infoSysStat(info)
	if err != nil || selfErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || owner.Uid != 0 || owner.Nlink != 1 || !os.SameFile(info, self) {
		return "", errors.New("地域核对程序身份与运行中版本不同")
	}
	return name, nil
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	return v, ok
}

func statisticsGeoVerifierArguments(unit, program string) []string {
	return []string{"--quiet", "--wait", "--pipe", "--collect", "--no-ask-password", "--service-type=exec", "--unit=" + unit,
		"--property=DynamicUser=yes", "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
		"--property=RestrictAddressFamilies=AF_UNIX", "--property=RestrictSUIDSGID=yes", "--property=KillMode=control-group",
		"--property=RuntimeMaxSec=300s", "--property=TimeoutStopSec=5s", "--property=MemoryMax=768M", "--property=MemoryHigh=512M",
		"--property=MemorySwapMax=0", "--property=TasksMax=32", "--property=CPUQuota=70%", "--property=LimitCORE=0",
		"--setenv=GOMEMLIMIT=512MiB", program, "--statistics-geodata-reader"}
}

func (s *Service) statisticsGeoStructureVerify(ctx context.Context, manifest geodata.Manifest, raw io.Reader) error {
	if os.Geteuid() != 0 || upgradeguard.Blocked() {
		return errors.New("地域后台核对受安装环境或升级保护阻止")
	}
	program, err := statisticsGeoVerifierProgram()
	if err != nil {
		return err
	}
	input, err := geodata.StructureInput(manifest, raw)
	if err != nil {
		return err
	}
	// A fixed manager-owned slot also excludes an orphaned verifier after an
	// executor crash. systemd refuses a second start; there is no --replace.
	unit, token := statisticsGeoVerifyUnit, core.ID()
	status, err := RunCommandWithTimeout(ctx, 3*time.Second, "/usr/bin/systemctl", "show", "--all", unit, "--property=LoadState,ActiveState,SubState,Environment")
	state, stateErr := statisticsGeoVerifyState(status)
	if err != nil || stateErr != nil || state["LoadState"] != "not-found" || state["ActiveState"] != "inactive" || state["SubState"] != "dead" || state["Environment"] != "" {
		return errors.New("已有地域校验单元或状态无法核对；不并行、覆盖或接管")
	}
	bounded, cancel := context.WithTimeout(ctx, 305*time.Second)
	defer cancel()
	args := statisticsGeoVerifierArguments(unit, program)
	args = append(args[:len(args)-2], "--setenv=PANEL_GEODATA_VERIFY_TOKEN="+token, program, "--statistics-geodata-reader")
	cmd := exec.CommandContext(bounded, "/usr/bin/systemd-run", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "SYSTEMD_COLORS=0"}
	cmd.Stdin = input
	out, diagnostic := &boundedBuffer{max: 128}, &boundedBuffer{max: 2048}
	cmd.Stdout = out
	cmd.Stderr = diagnostic
	cmd.WaitDelay = 5 * time.Second
	// Killing the client alone is insufficient. Stop the fixed slot only if its
	// exact private-call nonce is still present; never stop a foreign/raced job.
	// RuntimeMax independently terminates orphaned work.
	cmd.Cancel = func() error {
		stop, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		observed, observeErr := RunCommandWithTimeout(stop, 2*time.Second, "/usr/bin/systemctl", "show", "--all", unit, "--property=LoadState,ActiveState,SubState,Environment")
		if observeErr == nil && statisticsGeoVerifyOwned(observed, token) {
			_, _ = RunCommandWithTimeout(stop, 3*time.Second, "/usr/bin/systemctl", "stop", "--no-block", unit)
		}
		if cmd.Process != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	if err = cmd.Run(); err != nil || out.truncated || diagnostic.truncated || !bytes.Equal(out.Bytes(), []byte(geodata.StructureProtocol+manifest.SHA256+"\n")) {
		if bounded.Err() != nil {
			return bounded.Err()
		}
		return errors.New("独立限资源进程未返回匹配的完整地域结构核对结果")
	}
	return nil
}

// Early read-only CLI dispatch: no Service/DB/recovery constructors, paths,
// network access, installation or cache writes. The parent separately proves
// signatures; this sandbox independently proves the exact bytes and full tree.
func RunStatisticsGeoReader(input io.Reader, output io.Writer) error {
	if err := upgradeguard.CheckStartup(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return geodata.VerifyStructureStream(ctx, input, output)
}
