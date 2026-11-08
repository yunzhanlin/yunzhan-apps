package executor

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func streamAccountParentEvidencePermit() loadbalancestream.AccountChildPermit {
	return loadbalancestream.AccountChildPermit{JobID: strings.Repeat("a", 32), ParentPID: 1234, RunLockInode: 87654}
}

func TestLoadBalanceStreamAccountParentEvidenceRootStatus(t *testing.T) {
	raw := "Name:\tpanel-executor\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNoNewPrivs:\t1\n"
	if !streamAccountParentRootStatus([]byte(raw)) {
		t.Fatal("actual proc status field shape refused")
	}
	faults := []string{"", strings.Repeat("x", 65537), raw + "\x00", raw + "\r", raw + "Uid:\t0 0 0 0\n", raw + "Gid:\t0 0 0 0\n", raw + "NoNewPrivs:\t1\n"}
	for _, key := range []string{"Uid", "Gid", "NoNewPrivs"} {
		value := "\t0\t0\t0\t0"
		if key == "NoNewPrivs" {
			value = "\t1"
		}
		faults = append(faults, strings.Replace(raw, key+":"+value+"\n", "", 1))
		faults = append(faults, strings.Replace(raw, key+":"+value, key+":9", 1))
	}
	for i, v := range faults {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if streamAccountParentRootStatus([]byte(v)) {
				t.Fatal("untrusted/missing/duplicate Root process evidence accepted")
			}
		})
	}
}

func TestLoadBalanceStreamAccountParentEvidenceExactUnit(t *testing.T) {
	p := streamAccountParentEvidencePermit()
	unit, _ := loadbalancestream.AccountParentUnit(p.JobID)
	m := map[string]string{"Id": unit, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "1234", "ControlPID": "0", "ControlGroup": "/system.slice/" + unit, "NoNewPrivileges": "yes", "Slice": "system.slice"}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	raw := ""
	for _, key := range keys {
		raw += key + "=" + m[key] + "\n"
	}
	if !streamAccountParentUnitState([]byte(raw), p) {
		t.Fatal("exact nine actual systemctl properties refused")
	}
	for _, key := range keys {
		for _, fault := range []string{"missing", "duplicate", "foreign"} {
			t.Run(key+"/"+fault, func(t *testing.T) {
				v := raw
				switch fault {
				case "missing":
					v = strings.Replace(v, key+"="+m[key]+"\n", "", 1)
				case "duplicate":
					v += key + "=" + m[key] + "\n"
				case "foreign":
					v = strings.Replace(v, key+"="+m[key], key+"=foreign", 1)
				}
				if streamAccountParentUnitState([]byte(v), p) {
					t.Fatal("unit identity, original PID, cgroup or security property discarded")
				}
			})
		}
	}
	for _, v := range []string{raw + "Unknown=x\n", raw + "\n", strings.TrimSuffix(raw, "\n"), raw + "\x00", raw + "\r"} {
		if streamAccountParentUnitState([]byte(v), p) {
			t.Fatal("ambiguous unit output accepted")
		}
	}
}

func TestLoadBalanceStreamAccountParentEvidenceOriginalDescriptorLease(t *testing.T) {
	p := streamAccountParentEvidencePermit()
	raw := "pos:\t0\nflags:\t02000002\nmnt_id:\t29\nino:\t87654\nlock:\t1: FLOCK ADVISORY WRITE 1234 08:01:87654 0 EOF\n"
	if !streamAccountParentFDInfo([]byte(raw), p, 8, 1) {
		t.Fatal("single kernel-owned original RW descriptor lease refused")
	}
	faults := []string{"", strings.TrimSuffix(raw, "\n"), raw + "flags:\t02000002\n", raw + "unknown:\t1\n", raw + "lock:\t1: FLOCK ADVISORY WRITE 1234 08:01:87654 0 EOF\n", raw + "\r", raw + "\x00", strings.Repeat("x", 8193)}
	for _, change := range [][2]string{{"pos:\t0", "pos:\t1"}, {"02000002", "02000000"}, {"02000002", "02000001"}, {"mnt_id:\t29", "mnt_id:\t0"}, {"ino:\t87654", "ino:\t87655"}, {"WRITE 1234", "WRITE 1235"}, {"08:01:87654", "08:02:87654"}, {"08:01:87654", "08:01:87655"}, {"ADVISORY WRITE", "ADVISORY READ"}, {"FLOCK", "POSIX"}, {"0 EOF", "1 EOF"}, {"0 EOF", "0 1"}} {
		faults = append(faults, strings.Replace(raw, change[0], change[1], 1))
	}
	for _, key := range []string{"pos", "flags", "mnt_id", "ino", "lock"} {
		lines := strings.Split(raw, "\n")
		v := ""
		for _, line := range lines[:len(lines)-1] {
			if !strings.HasPrefix(line, key+":") {
				v += line + "\n"
			}
		}
		faults = append(faults, v)
	}
	for i, v := range faults {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if streamAccountParentFDInfo([]byte(v), p, 8, 1) {
				t.Fatal("foreign/ambiguous/released/wrong-mode descriptor lease accepted")
			}
		})
	}
}
