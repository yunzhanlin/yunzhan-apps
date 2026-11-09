package executor

import (
	"strings"
	"testing"
)

func TestNginxNativeWorkerRequiresCompleteClosedSupervisorBudget(t *testing.T) {
	valid := "Name:\tpanel-executor\nNoNewPrivs:\t1\nCapInh:\t00000000000000eb\nCapPrm:\t00000000000000eb\nCapEff:\t00000000000000eb\nCapBnd:\t00000000000000eb\nCapAmb:\t00000000000000eb\n"
	if err := validateNginxNativeWorkerCapabilities([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		for _, wrong := range []string{"0000000000000000", "000000000000006b", "00000000000000e5", "00000000000001eb", "000001ffffffffff", "00000000000000EB", "eb", "invalid"} {
			t.Run(key+"-"+wrong, func(t *testing.T) {
				if err := validateNginxNativeWorkerCapabilities([]byte(strings.Replace(valid, key+":\t00000000000000eb", key+":\t"+wrong, 1))); err == nil {
					t.Fatal("accepted incomplete or expanded supervisor grants")
				}
			})
		}
		for _, bad := range []string{strings.Replace(valid, key+":\t00000000000000eb\n", "", 1), valid + key + ":\t00000000000000eb\n"} {
			if err := validateNginxNativeWorkerCapabilities([]byte(bad)); err == nil {
				t.Fatal("accepted missing or duplicate capability", key)
			}
		}
	}
	for _, bad := range []string{"", valid[:len(valid)-1], valid + strings.Repeat("x", 32<<10), valid + "\x00", strings.ReplaceAll(valid, "\n", "\r\n"), strings.Replace(valid, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(valid, "NoNewPrivs:\t1\n", "", 1), valid + "NoNewPrivs:\t1\n"} {
		if err := validateNginxNativeWorkerCapabilities([]byte(bad)); err == nil {
			t.Fatal("accepted malformed privilege boundary")
		}
	}
}
