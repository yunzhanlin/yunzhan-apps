package executor

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Include parser stop/result checks, capture shutdown and durable file recovery.
// The prerequisite must outlive its bounded child, and API rollback must also
// allow a separately verified capture restart. These are not request timeouts.
const (
	threatIDSRecoveryBudget      = 180 * time.Second
	threatIDSRecoveryUnitSeconds = 210
	threatIDSRollbackBudget      = 330 * time.Second
	threatIDSOperationBudget     = 6 * time.Minute
)

var threatIDSUnitPrefix = regexp.MustCompile(`^apt-[a-f0-9]{16}$`)

func threatIDSGuardPath(path string) bool {
	return path == "/opt/panel/bin/panel-executor" || path == "/opt/panel/current/bin/panel-executor"
}

// The interface comes only from the fixed, revisioned YAML. A root read-only
// gate validates committed state or the live executor's locked candidate.
// Suricata still runs directly as the non-root account, never as the gate.
func threatIDSGatedUnit(prefix, guard string, privateLibraries ...bool) (string, error) {
	if !threatIDSGuardPath(guard) {
		return "", errors.New("IDS 启动核对程序不是固定面板执行器")
	}
	unit, err := threatIDSUnit(prefix, threatIDSConfig{Interface: "lo", HomeNetworks: []string{"127.0.0.1/32"}})
	if err != nil {
		return "", err
	}
	unit = strings.Replace(unit, "After=network-online.target\n", "After=network-online.target panel-network-ids-recover.service\nRequires=panel-network-ids-recover.service\n", 1)
	unit = strings.Replace(unit, "ExecStart=", "ExecStartPre=+"+guard+" --authorize-network-ids-start\nExecStart=", 1)
	return threatIDSUnitLibraryEnvironment(strings.Replace(unit, "--af-packet=lo ", "--af-packet ", 1), prefix, privateLibraries)
}

func threatIDSRecoveryUnit(guard string) (string, error) {
	if !threatIDSGuardPath(guard) {
		return "", errors.New("IDS 恢复程序不是固定面板执行器")
	}
	return fmt.Sprintf(`[Unit]
Description=Yunzhan private IDS configuration recovery
Before=panel-network-ids.service

[Service]
Type=oneshot
User=root
Group=root
ExecStart=%s --recover-network-ids
RemainAfterExit=yes
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/panel -/var/lib/panel-network-ids
RestrictAddressFamilies=AF_UNIX AF_NETLINK
MemoryMax=128M
MemorySwapMax=0
TasksMax=32
TimeoutStartSec=%d
`, guard, threatIDSRecoveryUnitSeconds), nil
}

// Exact earlier source only: retaining it permits read-only identity, safe
// stop and interrupted-journal recovery, not arbitrary administrator policy.
func threatIDSLegacyRecoveryUnit(guard string) (string, error) {
	v, err := threatIDSRecoveryUnit(guard)
	return strings.Replace(v, fmt.Sprintf("TimeoutStartSec=%d\n", threatIDSRecoveryUnitSeconds), "TimeoutStartSec=60\n", 1), err
}

func threatIDSRecoverySource(guard, digest string) (string, error) {
	for _, render := range []func(string) (string, error){threatIDSRecoveryUnit, threatIDSLegacyRecoveryUnit} {
		v, err := render(guard)
		if err == nil && digest == fmt.Sprintf("%x", sha256.Sum256([]byte(v))) {
			return v, nil
		}
	}
	return "", errors.New("IDS 恢复单元来源不是已知固定代次")
}

// A fixed systemd oneshot changes identity outside the deliberately restricted
// long-lived Go executor. The parser runs without ANY kernel capabilities;
// -T plus disabled EVE cannot start capture or write the active event log.
func threatIDSSyntaxUnit(prefix string, privateLibraries ...bool) (string, error) {
	if !threatIDSUnitPrefix.MatchString(prefix) {
		return "", errors.New("IDS 配置检查程序前缀无效")
	}
	unit := fmt.Sprintf(`[Unit]
Description=Yunzhan private nonroot IDS configuration check
ConditionFileNotEmpty=/etc/panel/network-ids/suricata.yaml

[Service]
Type=oneshot
RemainAfterExit=yes
User=panel-network-ids
Group=panel-network-ids
UMask=0077
ExecStart=/opt/panel/app-modules/network-threat-detection/%s/bin/suricata -T --init-errors-fatal --strict-rule-keywords --set outputs.0.eve-log.enabled=no -l /tmp -c /etc/panel/network-ids/suricata.yaml
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
MemoryMax=384M
MemorySwapMax=0
CPUQuota=60%%
TasksMax=32
LimitNOFILE=256
LimitCORE=0
LimitFSIZE=1M
TimeoutStartSec=90s
TimeoutStopSec=10s
KillMode=control-group
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=20
`, prefix)
	return threatIDSUnitLibraryEnvironment(unit, prefix, privateLibraries)
}

func threatIDSUnitLibraryEnvironment(unit, prefix string, isolated []bool) (string, error) {
	if len(isolated) > 1 || !threatIDSUnitPrefix.MatchString(prefix) {
		return "", errors.New("IDS 固定私有库单元参数无效")
	}
	if len(isolated) == 0 || !isolated[0] {
		return unit, nil
	}
	line := "Environment=\"LD_LIBRARY_PATH=/opt/panel/app-modules/network-threat-detection/" + prefix + "/libraries\" \"LD_PRELOAD=\" \"LD_AUDIT=\" \"LD_DEBUG=\"\n"
	return strings.Replace(unit, "UMask=0077\n", "UMask=0077\n"+line, 1), nil
}

// This process can observe packets but cannot administer interfaces/firewall,
// load modules, write panel configuration or execute request-provided code.
// No install/enable operation is performed by rendering this unit.
func threatIDSUnit(prefix string, in threatIDSConfig) (string, error) {
	if !threatIDSUnitPrefix.MatchString(prefix) {
		return "", errors.New("IDS 原生程序来源前缀无效")
	}
	if err := validateThreatIDSConfig(in); err != nil {
		return "", err
	}
	return fmt.Sprintf(`[Unit]
Description=Yunzhan passive network IDS
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=/etc/panel/network-ids/suricata.yaml

[Service]
Type=simple
User=panel-network-ids
Group=panel-network-ids
UMask=0077
ExecStart=/opt/panel/app-modules/network-threat-detection/%s/bin/suricata --init-errors-fatal --strict-rule-keywords --af-packet=%s --runmode=workers -c /etc/panel/network-ids/suricata.yaml
Restart=no
TimeoutStartSec=60
TimeoutStopSec=20
KillMode=control-group
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
RestrictAddressFamilies=AF_PACKET AF_INET AF_INET6 AF_UNIX AF_NETLINK
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
ReadWritePaths=/var/lib/panel-network-ids/logs
MemoryMax=384M
MemorySwapMax=0
CPUQuota=60%%
TasksMax=32
LimitNOFILE=256
LimitCORE=0
LimitFSIZE=8M
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=20

[Install]
WantedBy=multi-user.target
`, prefix, in.Interface), nil
}
