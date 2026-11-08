package executor

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func streamServiceStatusFixture() string {
	return "Name:\tnginx\nState:\tS (sleeping)\nUid:\t991\t991\t991\t991\nGid:\t992\t992\t992\t992\nGroups:\t992 \nThreads:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t4\n"
}

func TestLoadBalanceStreamServiceEvidenceRequiresActualZeroCapabilitiesAndDedicatedIdentity(t *testing.T) {
	raw := streamServiceStatusFixture()
	if !streamServiceProcessStatus([]byte(raw), 991, 992) {
		t.Fatal("valid owned zero-capability status refused")
	}
	for key, wrong := range map[string]string{"Uid": "0 0 0 0", "Gid": "0 0 0 0", "Groups": "992 999", "Threads": "2", "CapInh": "0000000000000001", "CapPrm": "0000000000000001", "CapEff": "0000000000000001", "CapBnd": "0000000000000001", "CapAmb": "0000000000000001", "NoNewPrivs": "0", "Seccomp": "0"} {
		t.Run(key, func(t *testing.T) {
			var changed, missing strings.Builder
			for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
				if strings.HasPrefix(line, key+":") {
					changed.WriteString(key + ":\t" + wrong + "\n")
				} else {
					changed.WriteString(line + "\n")
					missing.WriteString(line + "\n")
				}
			}
			for _, value := range []string{changed.String(), missing.String(), raw + key + ":\t" + wrong + "\n"} {
				if streamServiceProcessStatus([]byte(value), 991, 992) {
					t.Fatal("wrong, missing or ambiguous kernel identity accepted")
				}
			}
		})
	}
	for _, ids := range [][2]uint32{{0, 992}, {991, 0}, {99, 992}, {1000, 992}, {991, 1000}} {
		if streamServiceProcessStatus([]byte(raw), ids[0], ids[1]) {
			t.Fatal("non-dedicated identity accepted")
		}
	}
}

func TestLoadBalanceStreamServiceEvidenceExactDescriptorCPUAndPIDBounds(t *testing.T) {
	raw := "Limit                     Soft Limit           Hard Limit           Units\nMax cpu time              unlimited            unlimited            seconds\nMax open files            32768                32768                files\n"
	if !streamServiceOpenFiles([]byte(raw)) {
		t.Fatal("actual procfs rlimit grammar refused")
	}
	for _, changed := range []string{strings.Replace(raw, "32768", "32767", 1), strings.ReplaceAll(raw, "32768", "unlimited"), raw + "Max open files 32768 32768 files\n", "", raw + "\x00"} {
		if streamServiceOpenFiles([]byte(changed)) {
			t.Fatal("missing/ambiguous/different fd ceiling accepted")
		}
	}
	for _, v := range []string{"1000 1000\n", "100000 100000\n", "1000000 1000000\n"} {
		if !streamServiceCPU100([]byte(v)) {
			t.Fatal("actual equal quota/period rejected", v)
		}
	}
	for _, v := range []string{"max 100000\n", "200000 100000\n", "50000 100000\n", "0 0\n", "999 999\n", "1000001 1000001\n", "01000 01000\n", "1000  1000\n", "1000 1000", "1000 1000\r\n"} {
		if streamServiceCPU100([]byte(v)) {
			t.Fatal("unbounded or wrong CPU limit accepted", v)
		}
	}
	if got, ok := streamServicePIDs([]byte("219\n222\n")); !ok || !slices.Equal(got, []int{219, 222}) {
		t.Fatal("bounded actual cgroup process list refused")
	}
	for _, v := range []string{"", "1\n", "219\n219\n", "0219\n", "219\n\n", "219 222\n", "219", "2147483647\n"} {
		if _, ok := streamServicePIDs([]byte(v)); ok {
			t.Fatal("ambiguous process inventory accepted", v)
		}
	}
	var maximum strings.Builder
	for i := 2; i < 34; i++ {
		fmt.Fprintln(&maximum, i)
	}
	if _, ok := streamServicePIDs([]byte(maximum.String())); !ok {
		t.Fatal("32-task census maximum rejected")
	}
	if _, ok := streamServicePIDs([]byte(maximum.String() + "34\n")); ok {
		t.Fatal("33rd process escaped bounded census")
	}
}

func streamServicePropertiesFixture() map[string]string {
	values := map[string]string{"Id": loadbalancestream.ServiceUnitName, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "219", "ControlPID": "0", "ControlGroup": "/system.slice/" + loadbalancestream.ServiceUnitName, "InvocationID": strings.Repeat("a", 32), "Slice": "system.slice", "Transient": "yes", "User": "panel-lbstream", "Group": "panel-lbstream", "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "Restart": "no", "KillMode": "mixed", "KillSignal": "3", "RuntimeDirectory": "panel-load-balance-stream", "RuntimeDirectoryPreserve": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes", "RestrictRealtime": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "yes", "IPAccounting": "yes"}
	values["RemainAfterExit"] = "yes"
	return values
}

func streamServicePropertiesBytes(values map[string]string) []byte {
	var out strings.Builder
	for _, key := range streamServicePropertyNames {
		if value, exists := values[key]; exists {
			out.WriteString(key + "=" + value + "\n")
		}
	}
	return []byte(out.String())
}

func TestLoadBalanceStreamServiceEvidenceManagerIdentityCannotBeAnOldNameOrClaim(t *testing.T) {
	good := streamServicePropertiesBytes(streamServicePropertiesFixture())
	pid, invocation, err := decodeStreamServiceProperties(good)
	if err != nil || pid != 219 || invocation != strings.Repeat("a", 32) {
		t.Fatal("closed manager process identity rejected", err)
	}
	for _, key := range streamServicePropertyNames {
		t.Run(key, func(t *testing.T) {
			changed := streamServicePropertiesFixture()
			changed[key] = "wrong"
			missing := streamServicePropertiesFixture()
			delete(missing, key)
			for _, raw := range [][]byte{streamServicePropertiesBytes(changed), streamServicePropertiesBytes(missing), append(append([]byte{}, good...), []byte(key+"=duplicate\n")...)} {
				if _, _, err := decodeStreamServiceProperties(raw); err == nil {
					t.Fatal("wrong/missing/duplicate manager fact accepted", key)
				}
			}
		})
	}
	for _, bad := range []string{"1", "0", "0219", strconv.Itoa(1<<30 + 1)} {
		values := streamServicePropertiesFixture()
		values["MainPID"] = bad
		if _, _, err := decodeStreamServiceProperties(streamServicePropertiesBytes(values)); err == nil {
			t.Fatal("non-original PID accepted")
		}
	}
	for _, raw := range [][]byte{append(append([]byte{}, good...), []byte("Unexpected=yes\n")...), append(append([]byte{}, good...), '\r'), good[:len(good)-1]} {
		if _, _, err := decodeStreamServiceProperties(raw); err == nil {
			t.Fatal("unknown or truncated manager response accepted")
		}
	}
}
