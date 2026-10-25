//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func intrusionRemovalCandidateFixture(t *testing.T, arch string) (intrusionRuntimeState, intrusionEffectiveDump, string) {
	t.Helper()
	current := intrusionEffectiveRuntimeFixture(t, arch)
	raw := intrusionEffectiveARMFixture
	if arch == "amd64" {
		raw = intrusionEffectiveAMDFixture
	}
	effective, err := intrusionEffectiveConfigurationDecode(raw, current, current.Settings)
	if err != nil {
		t.Fatal(err)
	}
	var dump intrusionEffectiveDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		t.Fatal(err)
	}
	return current, dump, effective.Identity
}

func intrusionRemovalCandidateSet(t *testing.T, dump *intrusionEffectiveDump, key string, value any) {
	t.Helper()
	for _, cmd := range dump.Commands {
		if len(cmd) == 4 && cmd[0] == "set" && cmd[1] == "sshd" && cmd[2] == key {
			cmd[3] = value
			return
		}
		if len(cmd) == 5 && cmd[0] == "multi-set" && cmd[1] == "sshd" && cmd[2] == "action" {
			for _, item := range cmd[4].([]any) {
				pair := item.([]any)
				if pair[0] == key {
					pair[1] = value
					return
				}
			}
		}
	}
	t.Fatal("required private fixture field missing", key)
}

func TestIntrusionRemovalCandidateDerivesOnlyActualDumpLimitsAndPorts(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		for _, changed := range []bool{false, true} {
			t.Run(arch+map[bool]string{false: "/unchanged", true: "/different-baseline"}[changed], func(t *testing.T) {
				current, dump, beforeID := intrusionRemovalCandidateFixture(t, arch)
				wantedSettings := maps.Clone(current.Settings)
				wantedPorts := slices.Clone(current.Policy.Ports)
				if changed {
					wantedSettings = map[string]int{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 120}
					wantedPorts = []int{22, 2882}
					intrusionRemovalCandidateSet(t, &dump, "maxretry", float64(6))
					intrusionRemovalCandidateSet(t, &dump, "findtime", "11m")
					intrusionRemovalCandidateSet(t, &dump, "bantime", "2h")
					policy := current.Policy
					policy.Ports = wantedPorts
					values, err := intrusionStockActionValues(policy, current.Recipe.Values["nftables"], current.Recipe.Values["chain"])
					if err != nil {
						t.Fatal(err)
					}
					for _, field := range []string{"port", "actionstart", "actionflush"} {
						intrusionRemovalCandidateSet(t, &dump, field, values[field])
					}
				}
				raw, err := json.Marshal(dump)
				if err != nil {
					t.Fatal(err)
				}
				beforeRaw := bytes.Clone(raw)
				beforeRuntime, _ := json.Marshal(current)
				got, err := intrusionRemovalCandidateDecode(raw, current, beforeID)
				if err != nil || !maps.Equal(got.Settings, wantedSettings) || !slices.Equal(got.Ports, wantedPorts) || got.EffectiveIdentity != beforeID {
					t.Fatal("underlying values were guessed or other declarations changed", got, err)
				}
				got.Settings["max_retry"] = 9
				got.Ports[0] = 1234
				afterRuntime, _ := json.Marshal(current)
				if !bytes.Equal(raw, beforeRaw) || !bytes.Equal(beforeRuntime, afterRuntime) {
					t.Fatal("pure candidate modified its independent original observations")
				}
			})
		}
	}
}

func TestIntrusionRemovalCandidateRejectsUnknownDefaultsAndUnownedPolicyChanges(t *testing.T) {
	for name, change := range map[string]func(*intrusionEffectiveDump, *string){
		"missing-identity":   func(_ *intrusionEffectiveDump, id *string) { *id = "" },
		"different-identity": func(_ *intrusionEffectiveDump, id *string) { *id = strings.Repeat("b", 64) },
		"unknown-format":     func(d *intrusionEffectiveDump, _ *string) { d.Format = 2 },
		"missing-limit": func(d *intrusionEffectiveDump, _ *string) {
			for i, cmd := range d.Commands {
				if len(cmd) == 4 && cmd[1] == "sshd" && cmd[2] == "maxretry" {
					d.Commands = append(d.Commands[:i:i], d.Commands[i+1:]...)
					return
				}
			}
		},
		"duplicate-limit": func(d *intrusionEffectiveDump, _ *string) {
			d.Commands = append(d.Commands, []any{"set", "sshd", "maxretry", float64(5)})
		},
		"string-retry":    func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "maxretry", "5") },
		"fractional-time": func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "findtime", 600.5) },
		"permanent-ban":   func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "bantime", float64(-1)) },
		"unbounded-ban":   func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "bantime", "10081m") },
		"partial-minute":  func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "findtime", "601") },
		"unknown-unit": func(d *intrusionEffectiveDump, _ *string) {
			intrusionRemovalCandidateSet(t, d, "findtime", "10minutes")
		},
		"leading-zero":  func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "findtime", "0600") },
		"service-alias": func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "port", "ssh") },
		"all-ports":     func(d *intrusionEffectiveDump, _ *string) { intrusionRemovalCandidateSet(t, d, "port", "1:65535") },
		"changed-filter": func(d *intrusionEffectiveDump, _ *string) {
			intrusionRemovalCandidateSet(t, d, "prefregex", "^private-backend-sentinel$")
		},
		"changed-capacity": func(d *intrusionEffectiveDump, _ *string) {
			intrusionRemovalCandidateSet(t, d, "maxmatches", float64(6))
		},
		"custom-action": func(d *intrusionEffectiveDump, _ *string) {
			intrusionRemovalCandidateSet(t, d, "actionflush", "private-backend-sentinel")
		},
	} {
		t.Run(name, func(t *testing.T) {
			current, dump, beforeID := intrusionRemovalCandidateFixture(t, "arm64")
			change(&dump, &beforeID)
			raw, _ := json.Marshal(dump)
			original := bytes.Clone(raw)
			got, err := intrusionRemovalCandidateDecode(raw, current, beforeID)
			if err == nil || !reflect.DeepEqual(got, intrusionRemovalCandidate{}) || strings.Contains(err.Error(), "private-backend-sentinel") || !bytes.Equal(raw, original) {
				t.Fatal("unknown baseline became partial uninstall authority or leaked", got, err)
			}
		})
	}
	current, _, id := intrusionRemovalCandidateFixture(t, "arm64")
	for _, raw := range [][]byte{
		bytes.Replace(intrusionEffectiveARMFixture, []byte(`"format": 1`), []byte(`"format": 1, "FORMAT": 1`), 1),
		intrusionEffectiveARMFixture[:len(intrusionEffectiveARMFixture)/2],
		append(bytes.Clone(intrusionEffectiveARMFixture), []byte(`{}`)...),
		bytes.Repeat([]byte(" "), (32<<10)+1),
	} {
		if got, err := intrusionRemovalCandidateDecode(raw, current, id); err == nil || !reflect.DeepEqual(got, intrusionRemovalCandidate{}) {
			t.Fatal("nonclosed candidate stream accepted", err)
		}
	}
}
