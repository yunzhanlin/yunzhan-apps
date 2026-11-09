package executor

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestThreatIDSSyntaxUnitHasNoRootCapabilitiesCaptureOutputOrWritablePaths(t *testing.T) {
	v, err := threatIDSSyntaxUnit("apt-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v, "Type=oneshot\nRemainAfterExit=yes\n") {
		t.Fatal("successful parser execution can be garbage-collected before its result is verified")
	}
	for _, wanted := range []string{"User=panel-network-ids\n", "Group=panel-network-ids\n", "CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "NoNewPrivileges=true\n", "ProtectSystem=strict\n", "PrivateTmp=true\n", "MemoryMax=384M\n", "MemorySwapMax=0\n", "TimeoutStartSec=90s\n", "TimeoutStopSec=10s\n", " -T --init-errors-fatal --strict-rule-keywords --set outputs.0.eve-log.enabled=no -l /tmp -c /etc/panel/network-ids/suricata.yaml\n"} {
		if !strings.Contains(v, wanted) {
			t.Fatal("missing fixed nonroot check policy", wanted)
		}
	}
	for _, forbidden := range []string{"CAP_NET_RAW", "--af-packet", "User=root", "ExecStartPre=+", "ReadWritePaths=", "[Install]", "/bin/sh", "${", "%i"} {
		if strings.Contains(v, forbidden) {
			t.Fatal("parser can capture or receives dynamic/root privileges", forbidden)
		}
	}
	for _, bad := range []string{"apt-0123456789abcde", "apt-0123456789abcdef/../x", "apt-0123456789abcdef\nUser=root"} {
		if _, err := threatIDSSyntaxUnit(bad); err == nil {
			t.Fatal("unsafe parser program source accepted")
		}
	}
}

func TestThreatIDSGatedUnitFixedExecutorAndRecoveryBoundary(t *testing.T) {
	for _, guard := range []string{"/opt/panel/bin/panel-executor", "/opt/panel/current/bin/panel-executor"} {
		unit, err := threatIDSGatedUnit("apt-0123456789abcdef", guard)
		if err != nil || !strings.Contains(unit, "ExecStartPre=+"+guard+" --authorize-network-ids-start\n") || !strings.Contains(unit, "Requires=panel-network-ids-recover.service\n") || !strings.Contains(unit, "--af-packet --runmode=workers") || strings.Contains(unit, "--af-packet=") {
			t.Fatal("fixed startup gate/interface source missing", unit, err)
		}
		recovery, err := threatIDSRecoveryUnit(guard)
		if err != nil || !strings.Contains(recovery, "ExecStart="+guard+" --recover-network-ids\n") || strings.Contains(recovery, "/etc/nginx") || strings.Contains(recovery, "ExecStartPost") || strings.Contains(recovery, "[Install]") {
			t.Fatal(recovery, err)
		}
	}
	for _, guard := range []string{"/tmp/panel-executor", "/bin/sh", "/opt/panel/current/bin/panel-executor --other", "/opt/panel/bin/panel-executor\nExecStart=/bin/sh", ""} {
		if _, err := threatIDSGatedUnit("apt-0123456789abcdef", guard); err == nil {
			t.Fatal("arbitrary guard accepted", guard)
		}
		if _, err := threatIDSRecoveryUnit(guard); err == nil {
			t.Fatal("arbitrary recovery accepted", guard)
		}
	}
}

func TestThreatIDSUnitBoundedNonRootPassiveOnly(t *testing.T) {
	in := threatIDSConfig{Interface: "lo", HomeNetworks: []string{"127.0.0.1/32"}}
	unit, err := threatIDSUnit("apt-0123456789abcdef", in)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"User=panel-network-ids\n", "Group=panel-network-ids\n", "NoNewPrivileges=true\n", "CapabilityBoundingSet=CAP_NET_RAW\n", "AmbientCapabilities=CAP_NET_RAW\n", "ProtectSystem=strict\n", "ReadWritePaths=/var/lib/panel-network-ids/logs\n", "MemoryMax=384M\n", "MemorySwapMax=0\n", "LimitFSIZE=8M\n", "LimitCORE=0\n", "--af-packet=lo --runmode=workers -c /etc/panel/network-ids/suricata.yaml", "Restart=no\n"} {
		if !strings.Contains(unit, part) {
			t.Fatal("sandbox missing", part)
		}
	}
	for _, bad := range []string{"ConditionPathIsRegular", "CAP_NET_ADMIN", "CAP_SYS_ADMIN", "User=root", "ExecStart=/bin/", "--user=", " -D", "nfqueue", "ExecStartPost", "EnvironmentFile", "StateDirectory=", "DynamicUser="} {
		if strings.Contains(unit, bad) {
			t.Fatal("passive boundary widened", bad)
		}
	}
	for _, prefix := range []string{"", "apt-123", "apt-0123456789abcdef/../../bin", "apt-0123456789abcdef\nExecStart=/bin/sh", "apt-0123456789ABCDEF", "-y"} {
		if _, err := threatIDSUnit(prefix, in); err == nil {
			t.Fatal("untrusted prefix", prefix)
		}
	}
	in.Interface = "lo\nUser=root"
	if _, err := threatIDSUnit("apt-0123456789abcdef", in); err == nil {
		t.Fatal("interface injection")
	}
}

func TestThreatIDSRecoveryBudgetCompositionAndExactLegacySource(t *testing.T) {
	if threatIDSRecoveryBudget <= 110*time.Second+20*time.Second+35*time.Second || time.Duration(threatIDSRecoveryUnitSeconds)*time.Second <= threatIDSRecoveryBudget+20*time.Second || threatIDSRollbackBudget <= threatIDSRecoveryBudget+90*time.Second+40*time.Second || threatIDSOperationBudget <= threatIDSRollbackBudget {
		t.Fatal("a parent budget cannot outlive its complete bounded parser/recovery/start sequence")
	}
	for _, guard := range []string{"/opt/panel/current/bin/panel-executor", "/opt/panel/bin/panel-executor"} {
		current, err := threatIDSRecoveryUnit(guard)
		legacy, oldErr := threatIDSLegacyRecoveryUnit(guard)
		if err != nil || oldErr != nil || legacy != strings.Replace(current, "TimeoutStartSec=210\n", "TimeoutStartSec=60\n", 1) {
			t.Fatal("exact earlier recovery source is no longer reproducible", err, oldErr)
		}
		for _, wanted := range []string{current, legacy} {
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(wanted)))
			actual, err := threatIDSRecoverySource(guard, digest)
			if err != nil || actual != wanted {
				t.Fatal("known fixed source cannot be read for safe stop or journal recovery", err)
			}
		}
		for _, changed := range []string{strings.Replace(current, "TimeoutStartSec=210", "TimeoutStartSec=211", 1), strings.Replace(legacy, "TimeoutStartSec=60", "TimeoutStartSec=61", 1), current + "ExecStartPost=/bin/true\n"} {
			if _, err := threatIDSRecoverySource(guard, fmt.Sprintf("%x", sha256.Sum256([]byte(changed)))); err == nil {
				t.Fatal("administrator policy adopted as a known source")
			}
		}
	}
}
