package geodata

import (
	"bufio"
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestCountrySelectionRadixGeometryMatchesIndependentExplicitTrie(t *testing.T) {
	m, pub, private, files := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, private)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, codes := range [][]string{{"CN"}, {"CN", "US"}, {"AU", "CH", "CN", "US"}} {
		// Independent, deliberately allocating reference tree for the SMALL
		// fixture only; the production million-row merge stores no such map.
		nodes := map[string]bool{"0.0.0.0/0": true, "::/0": true}
		for _, code := range codes {
			scanner := bufio.NewScanner(bytes.NewReader(files[code]))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "#") {
					continue
				}
				prefix := netip.MustParsePrefix(strings.Fields(line)[0])
				for bit := 1; bit <= prefix.Bits(); bit++ {
					nodes[netip.PrefixFrom(prefix.Addr(), bit).Masked().String()] = true
				}
			}
			if scanner.Err() != nil {
				t.Fatal(scanner.Err())
			}
		}
		got, err := VerifyCountrySelection(context.Background(), a, codes, countrySelectionInputs(codes, files))
		if err != nil || got.RadixNodes != uint64(len(nodes)) || got.RadixNodes < uint64(got.Networks)+2 {
			t.Fatal("capacity geometry differs from actual explicit bit tree", codes, got, len(nodes), err)
		}
	}
}

func TestCountryRadixDeltaKeepsSharedPathsAndAddressFamiliesSeparate(t *testing.T) {
	for _, tc := range []struct {
		previous, next string
		nodes          uint64
	}{
		{"", "8.8.8.0/24", 24},
		{"8.8.8.0/24", "8.8.9.0/24", 1},
		{"8.8.8.0/24", "8.8.10.0/24", 2},
		{"8.8.8.0/24", "2606:4700::/32", 32},
		{"2606:4700::/32", "2607::/32", 17},
		{"2606:4700::/64", "2606:4700:0:1::/64", 1},
	} {
		var previous netip.Prefix
		if tc.previous != "" {
			previous = netip.MustParsePrefix(tc.previous)
		}
		got, err := countryRadixNodeDelta(previous, netip.MustParsePrefix(tc.next))
		if err != nil || got != tc.nodes {
			t.Fatal(tc, got, err)
		}
	}
	for _, pair := range [][2]string{{"8.8.8.0/24", "8.8.8.0/25"}, {"8.8.8.0/24", "8.8.8.1/32"}, {"8.8.9.0/24", "8.8.8.0/24"}, {"8.8.8.0/24", "8.8.9.1/24"}, {"2606:4700::/32", "8.8.8.0/24"}, {"8.8.8.0/24", "::ffff:8.8.9.0/120"}} {
		if got, err := countryRadixNodeDelta(netip.MustParsePrefix(pair[0]), netip.MustParsePrefix(pair[1])); err == nil || got != 0 {
			t.Fatal("ambiguous geometry accepted", pair, got, err)
		}
	}
}
