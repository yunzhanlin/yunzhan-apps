//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestIntrusionCurrentFamilyPlanChangesOnlyEachOutdatedOwnedHandle(t *testing.T) {
	for mask := 0; mask < 4; mask++ {
		for _, state := range []string{"committed", "rolled_back"} {
			t.Run(fmt.Sprintf("%d-%s", mask, state), func(t *testing.T) {
				p := intrusionJournalFixture(t)
				bans := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("2001:db8::2")}
				raw := intrusionMixedKernelFixture(t, p, mask)
				before := bytes.Clone(raw)
				out, err := planIntrusionCurrentFamilyPorts(p, raw, nil, bans, state)
				wanted := p.TargetPorts
				changed := 2 - bits.OnesCount(uint(mask))
				if state == "rolled_back" {
					wanted = p.BeforePolicy.Ports
					changed = 2 - changed
				}
				if err != nil || out.BeforeSHA256 != core.Hash(string(raw)) || !slices.Equal(out.TargetPorts, wanted) || len(out.Statements) != changed || len(out.RuleHandles) != changed || !bytes.Equal(raw, before) {
					t.Fatal(out.RuleHandles, err, changed)
				}
				handles := []uint64{}
				for i, h := range []uint64{3, 13} {
					after := mask&(1<<i) != 0
					if state == "committed" && !after || state == "rolled_back" && after {
						handles = append(handles, h)
					}
				}
				if !slices.Equal(out.RuleHandles, handles) {
					t.Fatal("unowned or already-current handle rewritten", out.RuleHandles, handles)
				}
				for _, line := range out.Statements {
					for _, forbidden := range []string{"127.0.0.", "2001:db8", "add ", "delete ", "flush ", "element ", "restart", "include", ";"} {
						if strings.Contains(line, forbidden) {
							t.Fatal("non-rule or historical replay escaped", forbidden)
						}
					}
				}
				if mask == 0 || mask == 3 {
					policy := p.BeforePolicy
					if mask == 3 {
						policy.Ports = slices.Clone(p.TargetPorts)
					}
					ordinary, err := planIntrusionNftPortChange(raw, intrusionPolicyScope(policy, bans), wanted)
					if err != nil || !reflect.DeepEqual(ordinary, out) {
						t.Fatal("uniform compatibility differs from independently verified planner", err)
					}
				}
			})
		}
	}
}

func TestIntrusionCurrentFamilyPlanCannotReturnFirstFamilyWhenSecondIsUnqualified(t *testing.T) {
	for _, kind := range []string{"second-family-comment", "original-rule-handle", "current-IP-mismatch", "third-port", "unknown-state"} {
		t.Run(kind, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			bans := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("2001:db8::2")}
			raw := intrusionMixedKernelFixture(t, p, 0)
			var doc map[string][]map[string]any
			json.Unmarshal(raw, &doc)
			for _, object := range doc["nftables"] {
				if rule, ok := object["rule"].(map[string]any); ok {
					set, _, _, err := intrusionNftRejectingRule(rule)
					if err != nil {
						t.Fatal(err)
					}
					if kind == "original-rule-handle" && set == p.BeforePolicy.IPv4Set {
						rule["handle"] = float64(91)
					}
					if set == p.BeforePolicy.IPv6Set {
						if kind == "second-family-comment" {
							rule["comment"] = "external-policy"
						}
						if kind == "third-port" {
							rule["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(4445)
						}
					}
				}
			}
			raw, _ = json.Marshal(doc)
			state := "committed"
			if kind == "unknown-state" {
				state = "commit --all"
			}
			if kind == "current-IP-mismatch" {
				bans = bans[:1]
			}
			out, err := planIntrusionCurrentFamilyPorts(p, raw, nil, bans, state)
			if err == nil || !reflect.DeepEqual(out, intrusionNftPortPlan{}) {
				t.Fatal("partial rule batch escaped failed qualification", err)
			}
		})
	}
}

func TestIntrusionCurrentFamilyPlanKeepsActualAbsentScopesWriteFree(t *testing.T) {
	for _, state := range []string{"table_absent", "scope_absent"} {
		t.Run(state, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			p.KernelState = state
			p.BansBefore = []string{}
			if state == "table_absent" {
				p.KernelBefore = nil
				p.KernelDirectory = []byte(`{"nftables":[]}`)
			} else {
				p.KernelBefore = intrusionNftEncode(t, intrusionLazySharedTable(t))
				p.KernelDirectory = nil
			}
			var err error
			p, err = intrusionJournalDerive(p)
			if err != nil {
				t.Fatal(err)
			}
			out, err := planIntrusionCurrentFamilyPorts(p, p.KernelBefore, p.KernelDirectory, nil, "committed")
			if err != nil || len(out.Statements) != 0 || len(out.RuleHandles) != 0 || !slices.Equal(out.TargetPorts, p.TargetPorts) {
				t.Fatal("absent scope generated synthetic objects", err)
			}
		})
	}
}
