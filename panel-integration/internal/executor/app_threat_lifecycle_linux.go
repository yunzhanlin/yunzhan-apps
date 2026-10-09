//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const threatIDSService = "panel-network-ids.service"

func (s *Service) threatIDSImmutable(ctx context.Context) (threatIDSRuntime, threatIDSAccount, threatIDSUnitRecord, error) {
	runtime, account, unit, err := s.threatIDSIdentity(ctx)
	if err != nil {
		return runtime, account, unit, err
	}
	for name, data := range threatIDSOriginalRuleFiles() {
		path := s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection/rules", name))
		if err := threatIDSTrustedParents(filepath.Dir(path), false); err != nil {
			return runtime, account, unit, err
		}
		digest, err := nfsFileDigest(path, 1<<20)
		info, statErr := os.Lstat(path)
		if err != nil || statErr != nil || info.Mode().Perm() != 0644 || digest != fmt.Sprintf("%x", sha256.Sum256([]byte(data))) {
			return runtime, account, unit, errors.New("IDS 固定规则或许可被外部修改")
		}
	}
	return runtime, account, unit, nil
}

// Identity is independent of rule/YAML health. Stopping an attested private
// process must remain possible when data is corrupt; starting still requires
// the full immutable rules, signed selected data and configuration gates.
func (s *Service) threatIDSIdentity(ctx context.Context) (threatIDSRuntime, threatIDSAccount, threatIDSUnitRecord, error) {
	runtime, err := s.threatIDSRuntime()
	if err != nil {
		return runtime, threatIDSAccount{}, threatIDSUnitRecord{}, err
	}
	account, err := s.threatIDSAccount(ctx)
	if err != nil {
		return runtime, account, threatIDSUnitRecord{}, err
	}
	unit, err := s.threatIDSUnitRecord(runtime)
	if err != nil {
		return runtime, account, unit, err
	}
	return runtime, account, unit, nil
}

func (s *Service) threatIDSNativeConfig(in threatIDSConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.threatIDSCommittedRuleProfile(ctx, in); err != nil {
		return err
	}
	wanted, err := threatIDSYAML(in, appNativeRoot+"/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		return err
	}
	path := s.systemPath("/etc/panel/network-ids/suricata.yaml")
	if err := threatIDSTrustedParents(filepath.Dir(path), false); err != nil {
		return err
	}
	actual, err := apacheWAFReadStableFile(path, 128<<10)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || info.Mode().Perm() != 0644 || !bytes.Equal(actual, []byte(wanted)) {
		return errors.New("IDS 原生配置与受管修订不同")
	}
	return nil
}

func (s *Service) threatIDSSyntax(ctx context.Context, runtime threatIDSRuntime, account threatIDSAccount) error {
	// Syntax checking must not open the live event output, even while capture
	// is running. Index 0 is fixed by our closed YAML, not by client input.
	args := []string{"-T", "--init-errors-fatal", "--strict-rule-keywords", "--set", "outputs.0.eve-log.enabled=no", "-l", "/tmp", "-c", "/etc/panel/network-ids/suricata.yaml"}
	if s.Config.SystemRoot != "/" {
		_, err := s.Config.Run(ctx, runtime.Binary, args...)
		return err
	}
	if validateThreatIDSAccount(account) != nil {
		return errors.New("IDS 检查账户无效")
	}
	if _, err := s.threatIDSUnitRecord(runtime); err != nil {
		return err
	}
	if err := s.threatIDSRequireCurrentSyntax(runtime); err != nil {
		return err
	}
	if err := s.threatIDSSyntaxIdleSource(ctx); err != nil {
		return err
	}
	const unit = "panel-network-ids-check.service"
	state, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", unit, "--property=ActiveState,SubState,MainPID")
	if err != nil || !threatIDSSyntaxIdle(state) {
		return errors.New("IDS 固定配置检查仍在执行或状态未知")
	}
	// RemainAfterExit retains a completed one's real exit status. Stop only
	// this verified idle fixed parser before every start, so an old successful
	// execution cannot be reused by systemctl start on an active exited unit.
	if _, err := s.moduleCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "stop", unit); err != nil {
		return errors.New("IDS 无法清除上次固定检查状态；未使用旧检查结果")
	}
	var before unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &before) != nil {
		return errors.New("IDS 配置检查启动时钟不可核对")
	}
	// The fixed parser has 90s plus a bounded 10s shutdown. Keep its caller
	// alive through that complete terminal state, not just the start timeout.
	if _, err := s.moduleCommand(ctx, 110*time.Second, "/usr/bin/systemctl", "start", unit); err != nil {
		return errors.New("IDS 固定非 root 配置检查失败；未退回 root 检查，专用单元日志保留")
	}
	result, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", unit, "--property=ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic")
	if err != nil {
		return err
	}
	var after unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &after) != nil {
		return errors.New("IDS 配置检查结束时钟不可核对")
	}
	return threatIDSSyntaxResult(result, before.Sec*1000000+before.Nsec/1000, after.Sec*1000000+after.Nsec/1000)
}

func threatIDSSyntaxResult(result string, earliest, latest int64) error {
	if len(result) > 4096 || earliest <= 0 || latest < earliest {
		return errors.New("IDS 配置检查结果或时钟范围无效")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(result), "\n") {
		key, value, ok := strings.Cut(line, "=")
		_, duplicate := values[key]
		if !ok || duplicate {
			return errors.New("IDS 配置检查结果字段重复或无效")
		}
		values[key] = value
	}
	started, parseErr := strconv.ParseInt(values["ExecMainStartTimestampMonotonic"], 10, 64)
	if len(values) != 6 || values["ActiveState"] != "active" || values["SubState"] != "exited" || values["MainPID"] != "0" || values["ExecMainCode"] != "1" || values["ExecMainStatus"] != "0" || parseErr != nil || strconv.FormatInt(started, 10) != values["ExecMainStartTimestampMonotonic"] || started < earliest || started > latest {
		return errors.New("IDS 没有本次真实执行成功的非 root 配置检查证据")
	}
	return nil
}

func threatIDSSyntaxIdle(result string) bool {
	if len(result) > 4096 {
		return false
	}
	v := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(result), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if _, exists := v[key]; exists {
			return false
		}
		v[key] = value
	}
	return len(v) == 3 && v["MainPID"] == "0" && (v["ActiveState"] == "active" && v["SubState"] == "exited" || v["ActiveState"] == "inactive" && v["SubState"] == "dead" || v["ActiveState"] == "failed" && v["SubState"] == "failed")
}

func (s *Service) threatIDSBootState(ctx context.Context) (bool, error) {
	value, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=UnitFileState", "--value")
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(value) {
	case "enabled":
		return true, nil
	case "disabled":
		return false, nil
	default:
		return false, errors.New("IDS 开机启动状态异常；未当作关闭或修改")
	}
}

func threatIDSCheckInterface(in threatIDSConfig) error {
	iface, err := net.InterfaceByName(in.Interface)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return errors.New("IDS 接口不存在或未启用；不自动启用网卡")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	addresses := []netip.Addr{}
	for _, raw := range addrs {
		p, err := netip.ParsePrefix(raw.String())
		if err == nil {
			addresses = append(addresses, p.Addr().Unmap())
		}
	}
	for _, raw := range in.HomeNetworks {
		network, _ := netip.ParsePrefix(raw)
		found := false
		for _, address := range addresses {
			if network.Contains(address) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("IDS 每个本机网段须包含所选接口的真实地址；不扩大监控范围")
		}
	}
	return nil
}

func (s *Service) threatIDSWaitCapture(ctx context.Context, runtime threatIDSRuntime, account threatIDSAccount, in threatIDSConfig) error {
	// Native controls run in the durable executor lane, not the request's
	// lifetime. Allow low-resource startup, but require this process's new EVE
	// counters within a bounded window; an active PID alone is insufficient.
	child, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		process, started, err := s.threatIDSProcess(child, runtime, in, account)
		if process && err == nil {
			report, readErr := s.readThreatIDSFile(child, account, threatEVEFilter{Limit: 1})
			if readErr != nil {
				return readErr
			}
			state := threatIDSCaptureState(report.Stats, time.Now().UTC(), started, true)
			if state == "observing" && !report.Partial {
				return nil
			}
			if state != "unknown" && state != "stale" {
				return fmt.Errorf("IDS 启动后实际采集状态：%s", state)
			}
		}
		select {
		case <-child.Done():
			return errors.New("IDS 未在预算内产生身份核对后的新鲜计数；没有宣布已采集")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *Service) threatIDSCheckRecoverySource(ctx context.Context, tx wafTransaction) (threatIDSRuntime, threatIDSAccount, error) {
	if len(tx.Changes) != 2 {
		return threatIDSRuntime{}, threatIDSAccount{}, errors.New("IDS 恢复来源不是完整两文件集合")
	}
	runtime, account, unit, err := s.threatIDSImmutable(ctx)
	if err != nil {
		return runtime, account, err
	}
	digest, err := nfsFileDigest(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
	if err != nil || tx.IDS == nil || digest != tx.IDS.RuntimeRecordSHA || unit.UnitSHA != tx.IDS.UnitSHA {
		return runtime, account, errors.New("IDS 事务的程序或单元来源已改变；保留证据且拒绝恢复")
	}
	boot, err := s.threatIDSBootState(ctx)
	if err != nil || boot != tx.IDS.WasEnabled {
		return runtime, account, errors.New("IDS 开机状态被外部改变；不覆盖外部选择")
	}
	// Independently recheck both pinned profiles before stopping capture or
	// restoring any file. A matching YAML is not evidence of rule integrity.
	for _, data := range [][]byte{tx.Changes[1].OldData, tx.Changes[1].NextData} {
		if len(data) == 0 {
			continue
		}
		var configuration threatIDSConfig
		if decodeThreatIDSPrivateJSON(data, &configuration) != nil || validateThreatIDSConfig(configuration) != nil {
			return runtime, account, errors.New("IDS 恢复规则的配置记录无效")
		}
		if _, err := s.threatIDSCommittedRuleProfile(ctx, configuration); err != nil {
			return runtime, account, err
		}
	}
	return runtime, account, nil
}

func (s *Service) recoverThreatIDSLocked(ctx context.Context, restoreRunning bool) error {
	tx, err := s.readWAFTransaction()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	runtime, account, err := s.threatIDSCheckRecoverySource(ctx, tx)
	if err != nil {
		return err
	}
	if err := s.threatIDSValidateRecoverySet(tx); err != nil {
		return err
	}
	if err := s.threatIDSRecoveryStopCapture(ctx, runtime, account, restoreRunning); err != nil {
		return err
	}
	if _, err := s.recoverWAFTransaction(); err != nil {
		return err
	}
	tx, err = s.readWAFTransaction()
	if err != nil {
		return err
	}
	next := tx.State == "committed"
	change := tx.Changes[1]
	data, exists := change.OldData, change.OldExists
	if next {
		data, exists = change.NextData, change.NextExists
	}
	if exists {
		var configuration threatIDSConfig
		if decodeThreatIDSPrivateJSON(data, &configuration) != nil {
			return errors.New("IDS 恢复记录配置无效")
		}
		if err := s.threatIDSNativeConfig(configuration); err != nil {
			return err
		}
		if err := s.threatIDSSyntax(ctx, runtime, account); err != nil {
			return err
		}
		if threatIDSResumeAfterRecovery(tx.IDS, restoreRunning) {
			owner, err := currentModuleApplyOwner()
			if err != nil {
				return err
			}
			// A failed dependency may re-run the prerequisite while this API
			// still owns the lock. Bind this recovery actor independently of
			// the original (possibly dead) applying process.
			tx.IDS.RecoveryOwner = owner
			if err := s.wafTransactionContract(tx); err != nil {
				return err
			}
			if err := wafWriteTransaction(s.wafPendingPath(), tx); err != nil {
				return err
			}
			if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", threatIDSService); err != nil {
				return err
			}
			if err := s.threatIDSWaitCapture(ctx, runtime, account, configuration); err != nil {
				return err
			}
		}
	} else if tx.IDS.WasActive {
		return errors.New("IDS 原配置不存在但记录为运行；保留恢复事务")
	}
	return s.finishWAFTransaction(tx)
}

// Validate the complete set before stopping/replacing files or authorizing
// startup. Unknown private-record edits cannot be hidden by a matching YAML.
func (s *Service) threatIDSValidateRecoverySet(tx wafTransaction) error {
	if err := s.wafTransactionContract(tx); err != nil {
		return err
	}
	for _, change := range tx.Changes {
		old, err := s.wafCurrentMatches(change, false)
		if err != nil {
			return err
		}
		next, err := s.wafCurrentMatches(change, true)
		if err != nil {
			return err
		}
		if tx.State == "applying" && !old && !next || tx.State == "committed" && !next || tx.State == "recovered" && !old {
			return errors.New("IDS 两文件恢复集合存在未知外部编辑；未停止或覆盖")
		}
	}
	return nil
}

func RecoverNetworkIDS() error {
	s := New(Config{}).threatIDSTransactionService()
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		return err
	}
	if _, err := os.Lstat(s.wafPendingPath()); os.IsNotExist(err) {
		return s.threatIDSStartOutputReady()
	} else if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), threatIDSRecoveryBudget)
	defer cancel()
	lock, err := s.lockWAFConfiguration()
	if errors.Is(err, errWAFConfigurationBusy) {
		tx, readErr := s.readWAFTransaction()
		if readErr != nil {
			return errors.New("IDS 恢复锁忙且不是有效候选事务")
		}
		if _, _, err := s.threatIDSCheckRecoverySource(ctx, tx); err != nil {
			return err
		}
		if err := s.threatIDSValidateRecoverySet(tx); err != nil {
			return err
		}
		owner := tx.IDS.ApplyOwner
		if tx.State != "applying" {
			owner = tx.IDS.RecoveryOwner
		}
		return s.authorizeModuleCandidate(ctx, filepath.Join(s.moduleDir("network-threat-detection"), "waf-configuration.lock"), owner)
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	// This is a prerequisite of capture itself: never synchronously start a
	// dependent unit from its own recovery prerequisite. The requested capture
	// start is verified by the gate after this file-only recovery completes.
	return s.recoverThreatIDSLocked(ctx, false)
}

func AuthorizeNetworkIDSStart() error {
	s := New(Config{}).threatIDSTransactionService()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if !s.moduleInstalled("network-threat-detection") {
		return errors.New("IDS 应用未安装；不启动留存的采集单元")
	}
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		return err
	}
	if err := s.threatIDSStartOutputReady(); err != nil {
		return err
	}
	runtime, _, _, err := s.threatIDSImmutable(ctx)
	if err != nil {
		return err
	}
	if err := threatIDSRequireSupported(runtime.Package.Version); err != nil {
		return err
	}
	if err := s.threatIDSRequireCurrentRecovery(runtime); err != nil {
		return err
	}
	tx, err := s.readWAFTransaction()
	if os.IsNotExist(err) {
		in, err := s.threatIDSConfig()
		if err != nil {
			return err
		}
		return s.threatIDSAuthorizeConfiguration(in)
	}
	if err != nil {
		return err
	}
	if _, _, err := s.threatIDSCheckRecoverySource(ctx, tx); err != nil {
		return err
	}
	if err := s.threatIDSValidateRecoverySet(tx); err != nil {
		return err
	}
	data := tx.Changes[1].OldData
	if tx.State == "applying" {
		if err := s.authorizeModuleCandidate(ctx, filepath.Join(s.moduleDir("network-threat-detection"), "waf-configuration.lock"), tx.IDS.ApplyOwner); err != nil {
			return err
		}
		data = tx.Changes[1].NextData
	} else if tx.State == "committed" {
		data = tx.Changes[1].NextData
	}
	var in threatIDSConfig
	if decodeThreatIDSPrivateJSON(data, &in) != nil || validateThreatIDSConfig(in) != nil {
		return errors.New("IDS 启动事务中的配置无效")
	}
	return s.threatIDSAuthorizeConfiguration(in)
}

func (s *Service) threatIDSAuthorizeConfiguration(in threatIDSConfig) error {
	if err := s.threatIDSNativeConfig(in); err != nil {
		return err
	}
	if s.Config.SystemRoot == "/" {
		return threatIDSCheckInterface(in)
	}
	return nil
}

func (s *Service) moduleThreatIDSControl(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if action == "ids-prepare" {
		if !in.PrepareIDS {
			return nil, errors.New("IDS 原生准备必须显式选择；打开报表不会触发")
		}
		_, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", "panel-app-dependencies@network-threat-detection")
		return map[string]any{"state": "preparing", "capture_started": false}, err
	}
	s = s.threatIDSTransactionService()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if s.Config.SystemRoot == "/" && !s.moduleInstalled("network-threat-detection") {
		return nil, errors.New("IDS 应用在任务接管前已卸载；未重建原生配置或启动")
	}
	if action == "ids-stop" {
		return s.stopAttestedThreatIDS(ctx, in.ExpectedRevision)
	}
	// Recovery dispatch is asynchronous, but the caller still has to review
	// the current configuration. Check the revision before any pending-runtime
	// shortcut; otherwise a stale form could dispatch the privileged installer.
	if action == "ids-recover" {
		current, readErr := s.threatIDSConfig()
		if readErr != nil && !os.IsNotExist(readErr) {
			return nil, readErr
		}
		if in.ExpectedRevision < 0 || in.ExpectedRevision != current.Revision {
			return nil, errors.New("IDS 修订冲突；刷新配置后重试")
		}
	}
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		if action == "ids-recover" {
			_, dispatchErr := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", "panel-app-dependencies@network-threat-detection")
			return map[string]any{"state": "recovering-runtime", "recovered": false, "capture_started": false}, dispatchErr
		}
		return nil, err
	}
	if action == "ids-recover" {
		rotation, err := s.readThreatIDSRotation()
		if err != nil {
			return nil, err
		}
		if rotation.Pending != nil || rotation.Retiring != nil {
			if _, err := os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
				return nil, errors.New("IDS 配置与输出同时存在待恢复集合；保留且拒绝混合恢复")
			}
			rotation, err = s.recoverThreatIDSOutputLocked(ctx, in.ExpectedRevision)
			return map[string]any{"recovered": err == nil, "capture_started": false, "rotation": rotation}, err
		}
		return map[string]any{"recovered": true}, s.recoverThreatIDSLocked(ctx, true)
	}
	if _, err := os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
		return nil, errors.New("IDS 仍有待恢复事务；先执行独立恢复，不自动覆盖")
	}
	runtime, account, unit, err := s.threatIDSImmutable(ctx)
	if err != nil {
		return nil, err
	}
	if action != "ids-boot" || in.Enabled {
		if err := s.threatIDSRequireCurrentRecovery(runtime); err != nil {
			return nil, err
		}
	}
	old, err := s.threatIDSConfig()
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if in.ExpectedRevision != old.Revision || in.ExpectedRevision < 0 {
		return nil, errors.New("IDS 修订冲突；刷新配置后重试")
	}
	rotation, err := s.readThreatIDSRotation()
	if err != nil {
		return nil, err
	}
	if (rotation.Pending != nil || rotation.Retiring != nil) && action != "ids-stop" && action != "ids-rotate" {
		return nil, errors.New("IDS 轮转仍待核对；不能修改配置、开机选择或启动，先核对恢复轮转")
	}
	if action == "ids-config" || action == "ids-rules" {
		next := old
		next.Revision = old.Revision + 1
		if action == "ids-config" {
			next.Interface = in.NetworkInterface
			next.HomeNetworks = append([]string{}, in.HomeNetworks...)
		} else {
			if old.Revision < 1 || in.RuleProfile == nil || core.ValidateNetworkIDSRuleProfile(*in.RuleProfile) != nil {
				return nil, errors.New("IDS 尚未配置或规则选择不完整；未使用默认规则")
			}
			next.RuleFeed = nil
			if in.RuleProfile.Selection != nil {
				selection := *in.RuleProfile.Selection
				next.RuleFeed = &selection
			}
		}
		if err := validateThreatIDSConfig(next); err != nil {
			return nil, err
		}
		if s.Config.SystemRoot == "/" {
			if err := threatIDSCheckInterface(next); err != nil {
				return nil, err
			}
		}
		wasActive := false
		if old.Revision != 0 {
			if err := s.threatIDSNativeConfig(old); err != nil {
				return nil, err
			}
			wasActive, _, err = s.threatIDSProcess(ctx, runtime, old, account)
			if err != nil {
				return nil, err
			}
		} else {
			state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
			if err != nil || !threatIDSStoppedUnit(state, false) {
				return nil, errors.New("IDS 无原配置但采集单元未明确停止；未保存")
			}
		}
		wasEnabled, err := s.threatIDSBootState(ctx)
		if wasActive {
			if supportErr := threatIDSRequireSupported(runtime.Package.Version); supportErr != nil {
				return nil, supportErr
			}
		}
		if err != nil {
			return nil, err
		}
		if old.Revision == 0 && wasEnabled {
			return nil, errors.New("IDS 没有配置但已设开机启动；需先核对外部状态")
		}
		owner, err := currentModuleApplyOwner()
		if err != nil {
			return nil, err
		}
		digest, err := nfsFileDigest(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
		if err != nil {
			return nil, err
		}
		yaml, err := threatIDSYAML(next, appNativeRoot+"/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
		if err != nil {
			return nil, err
		}
		if action == "ids-rules" && next.RuleFeed != nil {
			// New selection requires CURRENT authority even when an older
			// profile was already committed; expiry is never renewed by use.
			yaml, err = s.verifiedThreatIDSRuleDataYAML(ctx, next, *next.RuleFeed)
			if err != nil {
				return nil, err
			}
		}
		record, err := json.Marshal(next)
		if err != nil {
			return nil, err
		}
		changes := []wafConfigChange{}
		for i, path := range s.threatIDSConfigurationPaths() {
			backup, err := s.threatIDSStableBackup(path)
			if err != nil {
				return nil, err
			}
			data, mode := []byte(yaml), os.FileMode(0644)
			if i == 1 {
				data, mode = record, 0600
			}
			changes = append(changes, wafConfigChange{Path: path, OldData: backup.data, OldExists: backup.existed, OldMode: backup.mode, OldOwner: backup.owner, NextData: data, NextExists: true, NextMode: mode, NextOwner: backup.owner})
		}
		tx, err := s.startWAFTransactionState(changes, &threatIDSRecoveryState{WasActive: wasActive, WasEnabled: wasEnabled, UnitSHA: unit.UnitSHA, RuntimeRecordSHA: digest, ApplyOwner: owner})
		if err != nil {
			return nil, err
		}
		applyErr := func() error {
			if err := wafApplyChange(tx.Changes[0], true); err != nil {
				return err
			}
			if err := s.threatIDSSyntax(ctx, runtime, account); err != nil {
				return err
			}
			if err := s.threatIDSNativeConfig(next); err != nil {
				return err
			}
			if wasActive {
				if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "restart", threatIDSService); err != nil {
					return err
				}
				if err := s.threatIDSWaitCapture(ctx, runtime, account, next); err != nil {
					return err
				}
			}
			if err := wafApplyChange(tx.Changes[1], true); err != nil {
				return err
			}
			tx.State = "committed"
			return s.finishWAFTransaction(tx)
		}()
		if applyErr != nil {
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), threatIDSRollbackBudget)
			defer cancel()
			if rollbackErr := s.recoverThreatIDSLocked(rollbackCtx, true); rollbackErr != nil {
				return nil, fmt.Errorf("IDS 变更失败：%v；恢复未完成：%w；证据保留", applyErr, rollbackErr)
			}
			return nil, fmt.Errorf("IDS 变更失败，已恢复原配置和运行选择：%w", applyErr)
		}
		return map[string]any{"configuration": next, "running": wasActive, "boot_enabled": wasEnabled, "passive_only": true}, nil
	}
	if old.Revision < 1 {
		return nil, errors.New("IDS 尚未配置接口与本机网段")
	}
	if err := s.threatIDSNativeConfig(old); err != nil {
		return nil, err
	}
	switch action {
	case "ids-rotate":
		if _, err := s.rotateThreatIDSLockedChoice(ctx, true); err != nil {
			return nil, err
		}
	case "ids-start":
		if err := threatIDSRequireSupported(runtime.Package.Version); err != nil {
			return nil, err
		}
		if s.Config.SystemRoot == "/" {
			if err := threatIDSCheckInterface(old); err != nil {
				return nil, err
			}
		}
		if err := s.threatIDSSyntax(ctx, runtime, account); err != nil {
			return nil, err
		}
		if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", threatIDSService); err != nil {
			return nil, err
		}
		if err := s.threatIDSWaitCapture(ctx, runtime, account, old); err != nil {
			_, stopErr := s.Config.Run(context.WithoutCancel(ctx), "/usr/bin/systemctl", "stop", threatIDSService)
			return nil, fmt.Errorf("%v；已尝试停止未通过核对的采集：%v", err, stopErr)
		}
	case "ids-boot":
		operation := "disable"
		if in.Enabled {
			if err := threatIDSRequireSupported(runtime.Package.Version); err != nil {
				return nil, err
			}
			operation = "enable"
		}
		if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", operation, threatIDSService); err != nil {
			return nil, err
		}
		actual, err := s.threatIDSBootState(ctx)
		if err != nil || actual != in.Enabled {
			return nil, errors.New("IDS 开机选择写入后核对失败")
		}
	default:
		return nil, errors.New("未知 IDS 控制操作")
	}
	return s.observeThreatIDS(ctx, threatEVEFilter{}), nil
}
