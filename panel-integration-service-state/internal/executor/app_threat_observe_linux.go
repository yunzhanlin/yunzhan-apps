//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type threatIDSObservation struct {
	State               string                      `json:"capture_state"`
	Error               string                      `json:"error,omitempty"`
	Configuration       *threatIDSConfig            `json:"configuration"`
	RuleProfile         *threatIDSRuleProfileStatus `json:"rule_profile"`
	RuntimeReady        bool                        `json:"runtime_ready"`
	PreparationRequired bool                        `json:"preparation_required"`
	PreparationError    string                      `json:"preparation_error,omitempty"`
	EngineSupport       *threatIDSEngineSupport     `json:"engine_support"`
	BootEnabled         *bool                       `json:"boot_enabled"`
	ProcessVerified     bool                        `json:"process_verified"`
	StartedAt           string                      `json:"started_at,omitempty"`
	PassiveOnly         bool                        `json:"passive_only"`
	Report              threatEVEReport             `json:"events"`
	History             *threatIDSHistorySummary    `json:"retention"`
}

func (s *Service) moduleThreatIDSReport(ctx context.Context, in core.AppModuleInput) (any, error) {
	filter := threatEVEFilter{Search: in.Search, Limit: in.Limit, Offset: in.Offset}
	if in.Severity != "" {
		value, err := strconv.Atoi(in.Severity)
		if err != nil || strconv.Itoa(value) != in.Severity || value < 1 || value > 4 {
			return nil, errors.New("IDS 风险级别必须为 1–4 或留空")
		}
		filter.Severity = value
	}
	for _, pair := range []struct {
		value  string
		target *time.Time
	}{{in.FromTime, &filter.From}, {in.ToTime, &filter.To}} {
		if pair.value != "" {
			at, err := time.Parse(time.RFC3339Nano, pair.value)
			if err != nil || at.Year() < 2000 || at.Year() > 2100 {
				return nil, errors.New("IDS 时间筛选必须包含明确时区")
			}
			*pair.target = at
		}
	}
	if _, err := validateThreatEVEFilter(filter); err != nil {
		return nil, err
	}
	lock, err := s.threatIDSReadLock()
	if err != nil {
		return nil, err
	}
	if lock != nil {
		defer lock.Close()
	}
	return s.observeThreatIDS(ctx, filter), nil
}

func (s *Service) threatIDSConfig() (threatIDSConfig, error) {
	var v threatIDSConfig
	b, err := ftpPrivateRead(filepath.Join(s.moduleDir("network-threat-detection"), "ids-config.json"), 16<<10)
	if err != nil {
		return v, err
	}
	if decodeThreatIDSPrivateJSON(b, &v) != nil || v.Revision < 1 || validateThreatIDSConfig(v) != nil {
		return v, errors.New("IDS 已保存配置身份或修订无效；未套用默认网段")
	}
	return v, nil
}

func threatIDSUnitValues(output string) (map[string]string, error) {
	if len(output) > 32<<10 {
		return nil, errors.New("IDS 单元状态超过上限")
	}
	allowed := map[string]bool{"LoadState": true, "ActiveState": true, "MainPID": true, "ExecMainStartTimestampMonotonic": true, "User": true, "Group": true, "MemoryMax": true, "MemorySwapMax": true, "TasksMax": true, "LimitFSIZE": true, "ProtectSystem": true, "NoNewPrivileges": true, "CapabilityBoundingSet": true, "AmbientCapabilities": true}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || !allowed[k] || !threatEVEText(v, 256, false) {
			return nil, errors.New("IDS 单元状态字段无效")
		}
		if _, exists := out[k]; exists {
			return nil, errors.New("IDS 单元状态字段重复")
		}
		out[k] = v
	}
	if len(out) != len(allowed) {
		return nil, errors.New("IDS 单元状态字段缺失")
	}
	return out, nil
}

func threatIDSProcessStatus(status []byte, account threatIDSAccount) bool {
	if len(status) > 64<<10 || validateThreatIDSAccount(account) != nil {
		return false
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return false
		}
		fields[key] = strings.TrimSpace(value)
	}
	numeric := func(value string, wanted uint32) bool {
		values := strings.Fields(value)
		if len(values) != 4 {
			return false
		}
		for _, v := range values {
			if v != strconv.FormatUint(uint64(wanted), 10) {
				return false
			}
		}
		return true
	}
	// All five kernel capability sets must match the reviewed service. A
	// currently narrow effective set does not prove a narrow permitted or
	// inheritable set; missing values are not an implicit zero/default.
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if fields[key] != "0000000000002000" {
			return false
		}
	}
	return numeric(fields["Uid"], account.UID) && numeric(fields["Gid"], account.GID) && fields["NoNewPrivs"] == "1"
}

func (s *Service) threatIDSProcess(ctx context.Context, runtime threatIDSRuntime, in threatIDSConfig, account threatIDSAccount) (bool, time.Time, error) {
	return s.threatIDSProcessExpected(ctx, runtime, in, account, 0)
}

// A pinned pidfd must be bound to the same MainPID whose complete identity
// was verified. An independent second check of another process is not proof.
func (s *Service) threatIDSProcessExpected(ctx context.Context, runtime threatIDSRuntime, in threatIDSConfig, account threatIDSAccount, expectedPID int) (bool, time.Time, error) {
	output, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,MainPID,ExecMainStartTimestampMonotonic,User,Group,MemoryMax,MemorySwapMax,TasksMax,LimitFSIZE,ProtectSystem,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities", "panel-network-ids.service")
	if err != nil {
		return false, time.Time{}, errors.New("IDS 单元状态读取失败，未把故障当作停止或正常")
	}
	fields, err := threatIDSUnitValues(output)
	if err != nil {
		return false, time.Time{}, err
	}
	if fields["LoadState"] != "loaded" {
		return false, time.Time{}, errors.New("IDS 受管单元未加载或状态异常")
	}
	if fields["ActiveState"] == "inactive" {
		return false, time.Time{}, nil
	}
	if fields["ActiveState"] != "active" {
		return false, time.Time{}, fmt.Errorf("IDS 服务实际状态：%s", fields["ActiveState"])
	}
	expected := map[string]string{"User": "panel-network-ids", "Group": "panel-network-ids", "MemoryMax": "402653184", "MemorySwapMax": "0", "TasksMax": "32", "LimitFSIZE": "8388608", "ProtectSystem": "strict", "NoNewPrivileges": "yes", "CapabilityBoundingSet": "cap_net_raw", "AmbientCapabilities": "cap_net_raw"}
	for key, value := range expected {
		if fields[key] != value {
			return false, time.Time{}, errors.New("IDS 实际单元权限或资源预算与已审核策略不同")
		}
	}
	pid, err := strconv.Atoi(fields["MainPID"])
	if err != nil || pid <= 1 || expectedPID != 0 && pid != expectedPID {
		return false, time.Time{}, errors.New("IDS 活跃单元没有可信主进程")
	}
	procRoot := s.systemPath("/proc")
	startTicks, err := moduleProcessStart(procRoot, pid)
	if err != nil {
		return false, time.Time{}, err
	}
	actual, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return false, time.Time{}, errors.New("IDS 实际程序身份不可读取")
	}
	executable, err := os.Stat(runtime.Binary)
	if err != nil || !os.SameFile(actual, executable) {
		return false, time.Time{}, errors.New("IDS 主进程不是已核对的原生程序")
	}
	status, err := readModuleProcFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"), 64<<10)
	if err != nil || !threatIDSProcessStatus(status, account) {
		return false, time.Time{}, errors.New("IDS 实际进程 UID/GID 或 NET_RAW 权限边界不符")
	}
	command, err := readModuleProcFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"), 16<<10)
	want := []string{runtime.Binary, "--init-errors-fatal", "--strict-rule-keywords", "--af-packet", "--runmode=workers", "-c", "/etc/panel/network-ids/suricata.yaml"}
	if err != nil || string(command) != strings.Join(want, "\x00")+"\x00" {
		return false, time.Time{}, errors.New("IDS 实际启动参数与被动配置不同")
	}
	if runtime.Format == 3 {
		if err := s.threatIDSProcessPrivateLibraries(procRoot, pid, runtime); err != nil {
			return false, time.Time{}, err
		}
	}
	second, err := moduleProcessStart(procRoot, pid)
	if err != nil || second != startTicks {
		return false, time.Time{}, errors.New("IDS 在身份核对时退出或 PID 被复用")
	}
	micros, err := strconv.ParseInt(fields["ExecMainStartTimestampMonotonic"], 10, 64)
	var clock unix.Timespec
	if err != nil || micros <= 0 || unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock) != nil {
		return false, time.Time{}, errors.New("IDS 真实启动时间不可核对")
	}
	elapsed := clock.Sec*1000000 + clock.Nsec/1000 - micros
	if elapsed < 0 || elapsed > int64((time.Duration(1<<63-1))/time.Microsecond) {
		return false, time.Time{}, errors.New("IDS 启动单调时钟异常")
	}
	return true, time.Now().UTC().Add(-time.Duration(elapsed) * time.Microsecond), nil
}

func (s *Service) readThreatIDSFile(ctx context.Context, account threatIDSAccount, filter threatEVEFilter) (threatEVEReport, error) {
	file, size, err := s.openThreatIDSLiveFile(account)
	if err != nil {
		return threatEVEReport{}, err
	}
	if file == nil {
		return readThreatEVE(ctx, strings.NewReader(""), filter, false)
	}
	defer file.Close()
	return readThreatEVE(ctx, io.NewSectionReader(file, 0, size), filter, false)
}

func (s *Service) readThreatIDSRetainedFile(ctx context.Context, account threatIDSAccount, filter threatEVEFilter) (threatEVEReport, threatIDSHistorySummary, error) {
	history, summary, err := s.threatIDSHistorySources(ctx)
	if err != nil {
		return threatEVEReport{}, summary, err
	}
	file, size, err := s.openThreatIDSLiveFile(account)
	if err != nil {
		return threatEVEReport{}, summary, err
	}
	var live io.Reader = strings.NewReader("")
	if file != nil {
		defer file.Close()
		live = io.NewSectionReader(file, 0, size)
	}
	sources := append([]threatEVESource{{Reader: live, Live: true}}, history...)
	report, err := readThreatEVESources(ctx, sources, filter, false)
	return report, summary, err
}

func (s *Service) openThreatIDSLiveFile(account threatIDSAccount) (*os.File, int64, error) {
	if validateThreatIDSAccount(account) != nil {
		return nil, 0, errors.New("IDS 输出账户未核对")
	}
	parent := s.systemPath("/var/lib/panel-network-ids")
	if err := s.wafOwnedDirectory(parent, false); err != nil {
		return nil, 0, err
	}
	logdir := filepath.Join(parent, "logs")
	info, err := os.Lstat(logdir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != account.UID || info.Sys().(*syscall.Stat_t).Gid != account.GID {
		return nil, 0, errors.New("IDS 私有输出目录所有者或模式不符")
	}
	root, err := os.OpenRoot(logdir)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()
	file, err := root.OpenFile("eve.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 0 || st.Size() > threatEVEByteLimit || st.Sys().(*syscall.Stat_t).Uid != account.UID || st.Sys().(*syscall.Stat_t).Gid != account.GID || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		file.Close()
		return nil, 0, errors.New("IDS 输出不是有界的专用账户私有普通文件")
	}
	// Freeze a descriptor-size snapshot; never follow later links/renames or
	// keep chasing a growing log. Interrupted final JSON is reported partial.
	return file, st.Size(), nil
}

func (s *Service) observeThreatIDS(ctx context.Context, filter threatEVEFilter) threatIDSObservation {
	out := threatIDSObservation{State: "not-prepared", PassiveOnly: true, Report: threatEVEReport{Alerts: []threatEVEAlert{}, SeverityCounts: map[int]int{}}}
	valid, err := validateThreatEVEFilter(filter)
	if err != nil {
		out.State = "invalid-filter"
		out.Error = err.Error()
		return out
	}
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		out.State = "runtime-upgrade-pending"
		out.Error = err.Error()
		if configuration, err := s.threatIDSConfig(); err == nil {
			out.Configuration = &configuration
		}
		return out
	}
	runtime, err := s.threatIDSRuntime()
	if err != nil {
		if !os.IsNotExist(err) {
			out.State = "runtime-error"
			out.Error = err.Error()
		}
		return out
	}
	out.RuntimeReady = true
	support := threatIDSSupport(runtime.Package.Version, time.Now().UTC())
	out.EngineSupport = &support
	configuration, err := s.threatIDSConfig()
	if err != nil {
		out.State = "not-configured"
		if !os.IsNotExist(err) {
			out.State = "configuration-error"
			out.Error = err.Error()
		}
		return out
	}
	out.Configuration = &configuration
	for _, path := range []string{s.systemPath("/etc/panel/network-ids"), s.systemPath("/etc/systemd/system"), s.systemPath("/opt/panel/app-modules/network-threat-detection/rules")} {
		if err := s.wafOwnedDirectory(path, false); err != nil {
			out.State = "configuration-error"
			out.Error = "IDS 规则、配置或单元父目录身份异常"
			return out
		}
	}
	for name, data := range threatIDSOriginalRuleFiles() {
		path := s.systemPath(filepath.Join("/opt/panel/app-modules/network-threat-detection/rules", name))
		digest, err := nfsFileDigest(path, 1<<20)
		info, statErr := os.Lstat(path)
		if err != nil || statErr != nil || info.Mode().Perm() != 0644 || digest != fmt.Sprintf("%x", sha256.Sum256([]byte(data))) {
			out.State = "rules-error"
			out.Error = "IDS 固定原始规则或完整许可与已审核版本不同"
			return out
		}
	}
	if err := s.threatIDSNativeConfig(configuration); err != nil {
		out.State = "configuration-error"
		out.Error = "IDS 原生配置或已选规则的原始签名、完整文件不能核对；未启动或修复：" + err.Error()
		return out
	}
	profile, err := s.threatIDSCommittedRuleProfile(ctx, configuration)
	if err != nil {
		out.State = "rules-error"
		out.Error = err.Error()
		return out
	}
	out.RuleProfile = &profile
	if _, err := s.threatIDSUnitRecord(runtime); err != nil {
		out.State = "configuration-error"
		out.Error = "IDS 实际单元与固定权限策略不同；未启动或修复"
		return out
	}
	for _, check := range []func(threatIDSRuntime) error{s.threatIDSRequireCurrentSyntax, s.threatIDSRequireCurrentRecovery} {
		if err := check(runtime); err != nil {
			out.PreparationRequired = true
			out.PreparationError = err.Error()
			break
		}
	}
	account, err := s.threatIDSAccount(ctx)
	if err != nil {
		out.State = "account-error"
		out.Error = err.Error()
		return out
	}
	boot, err := s.threatIDSBootState(ctx)
	if err != nil {
		out.State = "configuration-error"
		out.Error = err.Error()
		return out
	}
	out.BootEnabled = &boot
	process, started, processErr := s.threatIDSProcess(ctx, runtime, configuration, account)
	out.ProcessVerified = process
	if process {
		out.StartedAt = started.Format(time.RFC3339Nano)
	}
	report, history, err := s.readThreatIDSRetainedFile(ctx, account, valid)
	out.History = &history
	if err != nil {
		out.State = "history-error"
		out.Error = err.Error()
		return out
	}
	out.Report = report
	out.State = threatIDSCaptureState(report.Stats, time.Now().UTC(), started, process)
	if processErr != nil {
		out.State = "process-error"
		out.Error = processErr.Error()
	}
	if process && report.Partial && out.State == "observing" {
		out.State = "output-incomplete"
	}
	if !support.Supported && (out.State == "observing" || out.State == "not-running" || out.State == "unknown" || out.State == "stale") {
		out.State = "engine-unsupported"
		out.Error = "程序来源已核对，但引擎维护状态不符合启动策略；采集计数不能证明旧版解析器安全。停止和历史查询仍可使用。"
	}
	return out
}
