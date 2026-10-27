package executor

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func streamAccountChildEvidenceFixture() (loadbalancestream.AccountChildPermit, map[string]string) {
	p := loadbalancestream.AccountChildPermit{Format: 1, AppVersion: loadbalancestream.AppVersion, JobID: strings.Repeat("a", 32), ActorID: strings.Repeat("b", 32), Nonce: strings.Repeat("c", 32), BootID: "12345678-1234-1234-1234-123456789abc", ParentPID: 1234, ParentStartTicks: 456,
		ParentExeSHA256: strings.Repeat("1", 64), ProgrammeInputsSHA256: strings.Repeat("2", 64), SeedSHA256: strings.Repeat("3", 64), AccountIntentSHA256: strings.Repeat("4", 64), JournalDevice: 11, JournalInode: 12, RunLockDevice: 11, RunLockInode: 13, CreatedAt: "2026-10-25T16:00:00Z"}
	parent, _ := loadbalancestream.AccountParentUnit(p.JobID)
	child, _ := loadbalancestream.AccountCreationUnit(p.JobID)
	return p, map[string]string{"Id": child, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "2345", "ControlPID": "0", "ControlGroup": "/system.slice/" + child, "NoNewPrivileges": "yes", "Slice": "system.slice", "Type": "exec", "BindsTo": parent, "After": "basic.target " + parent + " system.slice", "KillMode": "control-group", "RemainAfterExit": "no"}
}

func streamAccountChildEvidenceBytes(values map[string]string) []byte {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var raw strings.Builder
	for _, key := range keys {
		raw.WriteString(key + "=" + values[key] + "\n")
	}
	return []byte(raw.String())
}

func TestLoadBalanceStreamAccountChildEvidenceExactOwnUnitAndParentDependency(t *testing.T) {
	p, values := streamAccountChildEvidenceFixture()
	raw := streamAccountChildEvidenceBytes(values)
	if !streamAccountChildUnitState(raw, p, 2345) {
		t.Fatal("exact independently observed child properties refused")
	}
	for key, value := range values {
		for _, fault := range []string{"missing", "duplicate", "foreign"} {
			t.Run(key+"/"+fault, func(t *testing.T) {
				changed := string(raw)
				switch fault {
				case "missing":
					changed = strings.Replace(changed, key+"="+value+"\n", "", 1)
				case "duplicate":
					changed += key + "=" + value + "\n"
				case "foreign":
					changed = strings.Replace(changed, key+"="+value+"\n", key+"=foreign\n", 1)
				}
				if streamAccountChildUnitState([]byte(changed), p, 2345) {
					t.Fatal("missing/duplicate/foreign own process or parent dependency accepted")
				}
			})
		}
	}
	for _, pid := range []uint32{0, 1, p.ParentPID, 2346, 2147483648} {
		if streamAccountChildUnitState(raw, p, pid) {
			t.Fatal("another/self-parent/invalid PID accepted", pid)
		}
	}
	p.JobID = "../child"
	if streamAccountChildUnitState(raw, p, 2345) {
		t.Fatal("invalid original permit accepted")
	}
}

func TestLoadBalanceStreamAccountChildEvidenceBoundedOrderingIsNotParentBinding(t *testing.T) {
	p, values := streamAccountChildEvidenceFixture()
	parent, _ := loadbalancestream.AccountParentUnit(p.JobID)
	for _, after := range []string{parent, "system.slice " + parent, parent + " basic.target sysinit.target systemd-journald.socket"} {
		values["After"] = after
		if !streamAccountChildUnitState(streamAccountChildEvidenceBytes(values), p, 2345) {
			t.Fatal("normal independently added systemd ordering refused", after)
		}
	}
	for _, after := range []string{"", "basic.target", " " + parent, parent + " ", parent + "  system.slice", parent + " " + parent, parent + "\tother.service", parent + " ../other.service", parent + " other\\x2f.service", parent + " a\nb.service", parent + " " + strings.Repeat("a", 256)} {
		t.Run(strconv.Itoa(len(after))+"/"+strconv.Itoa(strings.Count(after, " ")), func(t *testing.T) {
			values["After"] = after
			if streamAccountChildUnitState(streamAccountChildEvidenceBytes(values), p, 2345) {
				t.Fatal("ambiguous/unbounded/missing original parent ordering accepted")
			}
		})
	}
	units := []string{parent}
	for i := 0; i < 32; i++ {
		units = append(units, "u"+strconv.Itoa(i)+".service")
	}
	values["After"] = strings.Join(units, " ")
	if streamAccountChildUnitState(streamAccountChildEvidenceBytes(values), p, 2345) {
		t.Fatal("oversized unit list accepted")
	}
	values["After"], values["BindsTo"] = parent, "unrelated.service"
	if streamAccountChildUnitState(streamAccountChildEvidenceBytes(values), p, 2345) {
		t.Fatal("ordering alone replaced the required live BindsTo dependency")
	}
}

func TestLoadBalanceStreamAccountChildEvidenceRefusesAmbiguousOutput(t *testing.T) {
	p, values := streamAccountChildEvidenceFixture()
	raw := string(streamAccountChildEvidenceBytes(values))
	for _, changed := range []string{"", raw + "\n", raw + "Unknown=yes\n", strings.TrimSuffix(raw, "\n"), raw + "\x00", raw + "\r", strings.Repeat("x", 8193)} {
		if streamAccountChildUnitState([]byte(changed), p, 2345) {
			t.Fatal("ambiguous/unbounded systemctl output accepted")
		}
	}
}
