//go:build linux

package executor

import (
	"strings"
	"testing"

	"local/panel/internal/core"
)

// Actual read-only installed Ubuntu24/ARM64 and Debian13/AMD64 observations:
// intrusion-known-chain24bhky, proof a764f703... and f0331273... respectively.
// This is configuration evidence, NOT an installed ban/SSH journey.
const intrusionObservedLazyStart = `nft add table inet f2b-table
nft -- add chain inet f2b-table f2b-chain \{ type filter hook input priority -1 \; \}
nft add set inet f2b-table <addr_set> \{ type <addr_type>\; \}
for proto in $(echo 'tcp' | sed 's/,/ /g'); do
nft add rule inet f2b-table f2b-chain $proto dport \{ $(echo '22' | sed s/:/-/g) \} <addr_family> saddr @<addr_set> reject
done
`

func TestIntrusionLazyChainMatchesCompleteObservedUpstreamWithoutExecuting(t *testing.T) {
	if core.Hash(intrusionObservedLazyStart) != "26c7f2f1ea716bfda20812136a11f4592b981227ef5433e1785dc76d32e1aad6" {
		t.Fatal("actual source observation changed")
	}
	for _, program := range []string{"nft", "/usr/sbin/nft", "/usr/bin/nft"} {
		raw := strings.ReplaceAll(intrusionObservedLazyStart, "nft ", program+" ")
		chain, err := intrusionNftLazyChain(raw, "f2b-table", []int{22})
		if err != nil || chain != "f2b-chain" {
			t.Fatal(chain, err)
		}
	}
	answers, read, _ := intrusionKernelFixture(t)
	answers["/usr/bin/fail2ban-client get sshd action nftables chain"] = "<known/chain>\n"
	answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = intrusionObservedLazyStart
	answers["/usr/sbin/nft -j list table inet f2b-table"] = string(intrusionNftEncode(t, intrusionLazySharedTable(t)))
	out, err := inspectIntrusionKernel(read, "nftables", []int{22}, nil)
	if err != nil || !out.Deferred || out.Verified || out.IPv4 || out.IPv6 {
		t.Fatal("resolved lazy chain became false protection", out, err)
	}
}

func TestIntrusionLazyChainRejectsPartialCustomOrInjectedRecipe(t *testing.T) {
	for name, raw := range map[string]string{
		"extra-command":  intrusionObservedLazyStart + "nft flush ruleset\n",
		"prefix-command": "true; " + intrusionObservedLazyStart,
		"wrong-table":    strings.ReplaceAll(intrusionObservedLazyStart, "f2b-table", "other-table"),
		"wrong-port":     strings.ReplaceAll(intrusionObservedLazyStart, "'22'", "'23'"),
		"wrong-hook":     strings.ReplaceAll(intrusionObservedLazyStart, "hook input", "hook output"),
		"wrong-priority": strings.ReplaceAll(intrusionObservedLazyStart, "priority -1", "priority -9"),
		"custom-set":     strings.ReplaceAll(intrusionObservedLazyStart, "<addr_set>", "custom_set"),
		"custom-verdict": strings.ReplaceAll(intrusionObservedLazyStart, "reject", "accept"),
		"unsafe-binary":  strings.ReplaceAll(intrusionObservedLazyStart, "nft ", "/tmp/nft "),
		"unknown-tag":    strings.ReplaceAll(intrusionObservedLazyStart, "f2b-chain", "<foreign/chain>"),
		"oversized":      strings.Repeat(" ", 4097),
	} {
		t.Run(name, func(t *testing.T) {
			chain, err := intrusionNftLazyChain(raw, "f2b-table", []int{22})
			if err == nil || chain != "" || strings.Contains(err.Error(), "flush ruleset") {
				t.Fatal("custom recipe interpreted or leaked", chain, err)
			}
		})
	}
}
