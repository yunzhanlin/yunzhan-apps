//go:build linux

package executor

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestIntrusionNftKnownAbsenceNeedsCompleteSuccessfulTypedDirectory(t *testing.T) {
	for _, raw := range []string{`{"nftables":[]}`, `{"nftables":[{"metainfo":{"version":"1.0.9","json_schema_version":1}},{"table":{"family":"inet","name":"other","handle":1}}]}`} {
		if err := intrusionNftTableKnownAbsent([]byte(raw), "f2b-table"); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string]string{
		"missing-root":    `{}`,
		"null-directory":  `{"nftables":null}`,
		"present-table":   `{"nftables":[{"table":{"family":"inet","name":"f2b-table","handle":1}}]}`,
		"duplicate-root":  `{"nftables":[],"nftables":[]}`,
		"duplicate-table": `{"nftables":[{"table":{"family":"ip","name":"other"}},{"table":{"family":"ip","name":"other"}}]}`,
		"unknown-object":  `{"nftables":[{"rule":{"accept":null}}]}`,
		"unknown-field":   `{"nftables":[{"table":{"family":"inet","name":"other","script":"list ruleset"}}]}`,
		"bad-handle":      `{"nftables":[{"table":{"family":"inet","name":"other","handle":-1}}]}`,
		"trailing":        `{"nftables":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := intrusionNftTableKnownAbsent([]byte(raw), "f2b-table"); err == nil {
				t.Fatal("unknown/present table promoted to known absence")
			}
		})
	}
}

func TestIntrusionKernelLazyAbsentTableIsDeferredNotVerifiedProtection(t *testing.T) {
	answers, read, calls := intrusionKernelFixture(t)
	answers["/usr/sbin/nft -j list table inet f2b-table"] = "ERROR"
	answers["/usr/sbin/nft -j list tables"] = `{"nftables":[]}`
	out, err := inspectIntrusionKernel(read, "nftables", []int{22}, nil)
	if err != nil || !out.Deferred || out.Verified || out.IPv4 || out.IPv6 || out.ActiveBans != 0 || *calls != 7 {
		t.Fatal("absence became kernel verification", out, err, *calls)
	}
	// A nonempty runtime ban list can never borrow a lazy/no-ban exception.
	out, err = inspectIntrusionKernel(read, "nftables", []int{22}, []netip.Addr{netip.MustParseAddr("127.0.0.2")})
	if err == nil || out.Deferred || out.Verified || *calls != 13 {
		t.Fatal("active ban with missing kernel accepted", out, err, *calls)
	}
	answers["/usr/sbin/nft -j list tables"] = `{"nftables":[{"table":{"family":"inet","name":"f2b-table"}}]}`
	if out, err = inspectIntrusionKernel(read, "nftables", []int{22}, nil); err == nil || out.Deferred || out.Verified {
		t.Fatal("table read failure hidden by existing table", out, err)
	}
}

func intrusionLazySharedTable(t *testing.T) map[string]any {
	t.Helper()
	v, _ := intrusionNftFixture(t)
	objects := []any{}
	for _, object := range intrusionNftObjects(v) {
		item := object.(map[string]any)
		if set, ok := item["set"].(map[string]any); ok && set["name"] == "addr-set-probe_sshd" {
			continue
		}
		if rule, ok := item["rule"].(map[string]any); ok && rule["handle"] == float64(3) {
			continue
		}
		objects = append(objects, object)
	}
	v["nftables"] = objects
	return v
}

func TestIntrusionKernelLazySharedTableRequiresCompleteNonBypassingChain(t *testing.T) {
	answers, read, _ := intrusionKernelFixture(t)
	answers["/usr/bin/fail2ban-client get sshd action nftables chain"] = "f2b-chain\n"
	answers["/usr/sbin/nft -j list table inet f2b-table"] = string(intrusionNftEncode(t, intrusionLazySharedTable(t)))
	out, err := inspectIntrusionKernel(read, "nftables", []int{22}, nil)
	if err != nil || !out.Deferred || out.Verified || out.IPv4 || out.IPv6 {
		t.Fatal(out, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"wrong-priority": func(v map[string]any) { intrusionNftChain(v)["prio"] = float64(0) },
		"orphan-set": func(v map[string]any) {
			v["nftables"] = append(intrusionNftObjects(v), map[string]any{"set": map[string]any{"family": "inet", "table": "f2b-table", "name": "addr-set-probe_sshd", "handle": float64(90), "type": "ipv4_addr", "elem": []any{}}})
		},
		"bypass": func(v map[string]any) {
			v["nftables"] = append(intrusionNftObjects(v), map[string]any{"rule": map[string]any{"family": "inet", "table": "f2b-table", "chain": "f2b-chain", "handle": float64(90), "expr": []any{map[string]any{"accept": nil}}}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := intrusionLazySharedTable(t)
			mutate(v)
			answers["/usr/sbin/nft -j list table inet f2b-table"] = string(intrusionNftEncode(t, v))
			out, err := inspectIntrusionKernel(read, "nftables", []int{22}, nil)
			if err == nil || out.Deferred || out.Verified {
				t.Fatal("partial or bypassing kernel classified as lazy", out, err)
			}
		})
	}
}

func TestIntrusionInspectionReportsDeferredNoBanStateWithoutHealthyOrWrites(t *testing.T) {
	s, answers, calls := intrusionInspectionFixture(t)
	answers["/usr/sbin/nft -j list table inet f2b-table"] = "ERROR"
	answers["/usr/sbin/nft -j list tables"] = `{"nftables":[]}`
	out, err := s.inspectIntrusion(context.Background())
	if err != nil || out.Healthy || out.KernelScopeVerified || !out.KernelScopeDeferred || !out.ActiveBansKnown || out.ActiveBans != 0 || !out.SSHPortsMatch || !out.ConfigMatches || len(out.Actions) != 1 || !out.Actions[0].KernelScopeDeferred || len(out.Warnings) != 1 || !strings.Contains(out.Actions[0].Detail, "等待首次实际封禁验证") || *calls != 19 {
		t.Fatal(out, err, *calls)
	}
}
