//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func intrusionMixedKernelFixture(t *testing.T, p intrusionJournalPlan, mask int) []byte {
	t.Helper()
	var doc map[string][]map[string]any
	if err := json.Unmarshal(intrusionTransactionDualKernel(t, p, p.BeforePolicy.Ports), &doc); err != nil {
		t.Fatal(err)
	}
	for _, object := range doc["nftables"] {
		if rule, ok := object["rule"].(map[string]any); ok {
			set, _, _, err := intrusionNftRejectingRule(rule)
			if err != nil {
				t.Fatal(err)
			}
			if set == p.BeforePolicy.IPv4Set && mask&1 != 0 || set == p.BeforePolicy.IPv6Set && mask&2 != 0 {
				rule["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = intrusionNftPortLiteral(p.TargetPorts)
			}
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIntrusionKernelProjectionRetainsEachCurrentFamilyWithoutRestoringHistory(t *testing.T) {
	for mask := 0; mask < 4; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			p := intrusionJournalFixture(t)
			bans := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("2001:db8::2")}
			raw := intrusionMixedKernelFixture(t, p, mask)
			before := bytes.Clone(raw)
			out, err := intrusionProjectCurrentKernelPorts(p, raw, bans)
			if err != nil || out.Deferred || len(out.PortsBySet) != 2 || out.ObservedSHA256 != core.Hash(string(raw)) || !bytes.Equal(raw, before) {
				t.Fatal(out.Deferred, err)
			}
			for i, set := range []string{p.BeforePolicy.IPv4Set, p.BeforePolicy.IPv6Set} {
				wanted := p.BeforePolicy.Ports
				if mask&(1<<i) != 0 {
					wanted = p.TargetPorts
				}
				if !slices.Equal(out.PortsBySet[set], wanted) {
					t.Fatal("current-family evidence rewritten")
				}
			}
			if _, err := inspectIntrusionNftScope(out.Projected, intrusionPolicyScope(p.BeforePolicy, bans)); err != nil {
				t.Fatal("projection lost typed policy/current bans", err)
			}
			if mask == 1 || mask == 2 {
				if intrusionKernelUniformPorts(out.PortsBySet) != nil {
					t.Fatal("mixed families became a fake uniform scope")
				}
				for _, ports := range [][]int{p.BeforePolicy.Ports, p.TargetPorts} {
					policy := p.BeforePolicy
					policy.Ports = ports
					if _, err := inspectIntrusionNftScope(raw, intrusionPolicyScope(policy, bans)); err == nil {
						t.Fatal("ordinary validator accepted mixed families")
					}
				}
			} else if len(intrusionKernelUniformPorts(out.PortsBySet)) == 0 {
				t.Fatal("uniform observed scope lost")
			}
		})
	}
}

func TestIntrusionKernelProjectionRejectsThirdFamilyScopesAndInvalidJSONBeforeNormalization(t *testing.T) {
	for _, kind := range []string{"third-v4", "third-v6", "family-set", "duplicate-own", "duplicate-JSON", "extra-root", "unmatched-ban", "bypass"} {
		t.Run(kind, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			bans := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("2001:db8::2")}
			raw := intrusionMixedKernelFixture(t, p, 1)
			var doc map[string][]map[string]any
			json.Unmarshal(raw, &doc)
			for _, object := range doc["nftables"] {
				rule, ok := object["rule"].(map[string]any)
				if !ok {
					continue
				}
				set, _, _, err := intrusionNftRejectingRule(rule)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "third-v4" && set == p.BeforePolicy.IPv4Set || kind == "third-v6" && set == p.BeforePolicy.IPv6Set {
					rule["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(2222)
				}
				if set != p.BeforePolicy.IPv4Set {
					continue
				}
				if kind == "family-set" {
					rule["expr"].([]any)[1].(map[string]any)["match"].(map[string]any)["right"] = "@" + p.BeforePolicy.IPv6Set
				}
				if kind == "duplicate-own" {
					doc["nftables"] = append(doc["nftables"], map[string]any{"rule": rule})
				}
				if kind == "bypass" {
					rule["expr"].([]any)[2] = map[string]any{"accept": nil}
				}
			}
			raw, _ = json.Marshal(doc)
			switch kind {
			case "duplicate-JSON":
				raw = []byte(strings.Replace(string(raw), `"nftables":`, `"nftables":[],"nftables":`, 1))
			case "extra-root":
				raw = []byte(strings.Replace(string(raw), `"nftables":`, `"force":true,"nftables":`, 1))
			case "unmatched-ban":
				bans = bans[:1]
			}
			out, err := intrusionProjectCurrentKernelPorts(p, raw, bans)
			if err == nil || !reflect.DeepEqual(out, intrusionKernelPortProjection{}) {
				t.Fatal("invalid current scope escaped as a partial plan", err)
			}
		})
	}
}

func TestIntrusionKernelProjectionKeepsGenuineDeferredScopeEmptyWithoutCreatingObjects(t *testing.T) {
	p := intrusionJournalFixture(t)
	raw := intrusionNftEncode(t, intrusionLazySharedTable(t))
	before := bytes.Clone(raw)
	p.KernelState, p.KernelBefore, p.BansBefore = "scope_absent", bytes.Clone(raw), []string{}
	var deriveErr error
	p, deriveErr = intrusionJournalDerive(p)
	if deriveErr != nil {
		t.Fatal(deriveErr)
	}
	out, err := intrusionProjectCurrentKernelPorts(p, raw, nil)
	if err != nil || !out.Deferred || len(out.PortsBySet) != 0 || intrusionKernelUniformPorts(out.PortsBySet) != nil || !bytes.Equal(raw, before) {
		t.Fatal(out.Deferred, err)
	}
}

func TestIntrusionOriginalKernelAcceptanceKeepsMixedFamilyPortsAndCannotReportCommitted(t *testing.T) {
	for mask := 0; mask < 4; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			p := intrusionJournalFixture(t)
			bans := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("2001:db8::2")}
			raw := intrusionMixedKernelFixture(t, p, mask)
			out, err := intrusionJournalKernelAccept(p, raw, nil, bans)
			if err != nil || out.State != "rules_observed" || len(out.PortsBySet) != 2 || len(out.StaticIdentity) != 64 {
				t.Fatal(out.State, err)
			}
			policy := p.BeforePolicy
			policy.Ports = slices.Clone(p.TargetPorts)
			var recipe intrusionActionRecipe
			if err := json.Unmarshal([]byte(intrusionActionRecipeFixture(t, policy)), &recipe); err != nil {
				t.Fatal(err)
			}
			live := intrusionRuntimeState{Process: p.ProcessBefore, ProcessStart: p.ProcessStartBefore, JournalMatch: p.JournalMatchBefore, Policy: policy, Recipe: recipe, Settings: p.TargetSettings, KernelState: out.State, KernelScopePorts: out.Ports, KernelPortsBySet: out.PortsBySet, Bans: bans}
			err = intrusionJournalRuntimeAt(p, live, "committed")
			if (err == nil) != (mask == 3) {
				t.Fatal("mixed or old family scope reported committed", mask, err)
			}
		})
	}
}

func TestIntrusionOriginalKernelMixedPortsStillRequireEveryRetainedHandleAndOtherPolicy(t *testing.T) {
	for _, kind := range []string{"owned-rule-handle", "owned-set-handle", "chain-handle", "other-rule", "owned-comment"} {
		t.Run(kind, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			bans := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("2001:db8::2")}
			var doc map[string]any
			json.Unmarshal(intrusionMixedKernelFixture(t, p, 1), &doc)
			switch kind {
			case "owned-rule-handle":
				intrusionNftOwnRule(doc)["handle"] = float64(91)
			case "owned-set-handle":
				intrusionNftOwnSet(doc)["handle"] = float64(92)
			case "chain-handle":
				intrusionNftChain(doc)["handle"] = float64(93)
			case "owned-comment":
				intrusionNftOwnRule(doc)["comment"] = "external-policy"
			case "other-rule":
				found := false
				for _, object := range intrusionNftObjects(doc) {
					if rule, ok := object.(map[string]any)["rule"].(map[string]any); ok {
						set, _, _, err := intrusionNftRejectingRule(rule)
						if err != nil {
							t.Fatal(err)
						}
						if set != p.BeforePolicy.IPv4Set && set != p.BeforePolicy.IPv6Set {
							rule["handle"] = float64(94)
							found = true
						}
					}
				}
				if !found {
					t.Fatal("missing unowned rule fixture")
				}
			}
			out, err := intrusionJournalKernelAccept(p, intrusionNftEncode(t, doc), nil, bans)
			if err == nil || !reflect.DeepEqual(out, intrusionTransactionKernel{}) {
				t.Fatal("mixed scopes bypassed original static identity", err)
			}
		})
	}
}

func TestIntrusionPendingRuntimeRechecksPerFamilyMapNotOnlyNormalizedIdentity(t *testing.T) {
	for _, swap := range []bool{false, true} {
		t.Run(fmt.Sprint(swap), func(t *testing.T) {
			s, answers, _, lock, p, raw := intrusionPendingObservationFixture(t)
			answers["/usr/bin/fail2ban-client get sshd banip"] = "127.0.0.3 2001:db8::2\n"
			key := "/usr/sbin/nft -j list table inet f2b-table"
			answers[key] = string(intrusionMixedKernelFixture(t, p, 1))
			run := s.Config.Run
			changed := false
			s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
				result, err := run(ctx, program, args...)
				if swap && !changed && program == "/usr/sbin/nft" {
					answers[key] = string(intrusionMixedKernelFixture(t, p, 2))
					changed = true
				}
				return result, err
			}
			out, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw)
			if (err != nil) != swap {
				t.Fatal("same normalized identity hid changed family scopes", err)
			}
			if !swap && (len(out.KernelPortsBySet) != 2 || len(out.KernelScopePorts) != 0) {
				t.Fatal("stable mixed observation lost exact family map")
			}
		})
	}
}
