package geodata

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// Actual tiny MMDB trees and ordinary signed Open; these are synthetic data,
// not evidence of provider coverage, a native Nginx install or app acceptance.
func countryFixture(t *testing.T, prefix netip.Prefix, split bool, row map[string]any) *Snapshot {
	t.Helper()
	bits := prefix.Bits()
	if bits < 1 || prefix != prefix.Masked() {
		t.Fatal("invalid fixture prefix")
	}
	address := prefix.Addr().AsSlice()
	version := uint32(6)
	if prefix.Addr().Is4() {
		// DB-IP's accepted format is an IPv6 MMDB with its IPv4 subtree at
		// ::/96, not a different IPv4-only provider/database format.
		address = make([]byte, 16)
		copy(address[12:], prefix.Addr().AsSlice())
		bits += 96
	}
	nodes := bits
	if split {
		nodes++
	}
	tree := make([]byte, nodes*6)
	put := func(node, side int, pointer uint32) {
		offset := node*6 + side*3
		tree[offset] = byte(pointer >> 16)
		tree[offset+1] = byte(pointer >> 8)
		tree[offset+2] = byte(pointer)
	}
	for node := 0; node < nodes; node++ {
		put(node, 0, uint32(nodes))
		put(node, 1, uint32(nodes))
	}
	data := uint32(nodes + 16)
	for bit := 0; bit < bits; bit++ {
		side := int((address[bit/8] >> uint(7-bit%8)) & 1)
		pointer := uint32(bit + 1)
		if bit == bits-1 && !split {
			pointer = data
		}
		put(bit, side, pointer)
	}
	if split {
		put(bits, 0, data)
		put(bits, 1, data)
	}
	raw := append(tree, make([]byte, 16)...)
	raw = append(raw, mmdbValue(row)...)
	raw = append(raw, []byte("\xAB\xCD\xEFMaxMind.com")...)
	metadata := map[string]any{"node_count": uint32(nodes), "record_size": uint32(24), "ip_version": version, "database_type": "DBIP-City-Lite", "binary_format_major_version": uint32(2), "binary_format_minor_version": uint32(0), "build_epoch": uint64(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix()), "languages": []any{"en", "zh-CN"}, "description": map[string]any{"en": "Country export fixture"}}
	raw = append(raw, mmdbValue(metadata)...)
	compressed := gzipFixture(t, raw)
	authority, _, _, _, _ := testAuthority(t, manifestFor(raw, compressed))
	snapshot, err := Open(context.Background(), authority, bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { snapshot.Close() })
	return snapshot
}

func TestCountryPrefixesActualVerifiedIPv4IPv6TreesAndSiblingCoalescing(t *testing.T) {
	for _, text := range []string{"8.8.8.0/24", "2606:4700::/32"} {
		t.Run(text, func(t *testing.T) {
			prefix := netip.MustParsePrefix(text)
			s := countryFixture(t, prefix, true, fixtureRecord())
			got, err := s.CountryPrefixes(context.Background(), []string{"CN", "US"}, 4)
			if err != nil {
				t.Fatal(err)
			}
			if got.RecordsVisited != 2 || !reflect.DeepEqual(got.Networks, []CountryNetwork{{Prefix: prefix, CountryCode: "US"}}) || got.ManifestSHA256 != s.authority.digest || got.DatabaseSHA256 != s.authority.manifest.SHA256 {
				t.Fatalf("not exact complete export: %+v", got)
			}
			if s.Lookup(prefix.Addr().String()).CountryCode != "US" {
				t.Fatal("ordinary lookup changed")
			}
			none, err := s.CountryPrefixes(context.Background(), []string{"CN"}, 4)
			if err != nil || len(none.Networks) != 0 || none.RecordsVisited != 2 {
				t.Fatalf("zero coverage not explicit: %+v %v", none, err)
			}
		})
	}
}

func TestCountryPublicPrefixesNeverWidenOrLocateSpecialUse(t *testing.T) {
	for _, text := range []string{"0.0.0.0/0", "::/0", "2000::/3", "10.0.0.0/8", "2001:db8::/32"} {
		prefix := netip.MustParsePrefix(text)
		parts := countryPublicPrefixes(prefix)
		for i, part := range parts {
			if !prefix.Contains(part.Addr()) || part.Bits() < prefix.Bits() || part != part.Masked() {
				t.Fatal("widened provider data", text, part)
			}
			for _, blocked := range excluded {
				if part.Overlaps(blocked) {
					t.Fatal("special-use leak", part, blocked)
				}
			}
			if i > 0 && (parts[i-1].Overlaps(part) || parts[i-1].Addr().Compare(part.Addr()) >= 0) {
				t.Fatal("overlapping/unordered public parts")
			}
		}
		if (text == "10.0.0.0/8" || text == "2001:db8::/32") && len(parts) != 0 {
			t.Fatal("private/documentation network exported")
		}
	}
	for _, text := range []string{"8.8.8.0/24", "2606:4700::/32"} {
		p := netip.MustParsePrefix(text)
		if !reflect.DeepEqual(countryPublicPrefixes(p), []netip.Prefix{p}) {
			t.Fatal("public prefix changed", p)
		}
	}
}

type countryCancelContext struct {
	context.Context
	calls int
}

func (c *countryCancelContext) Err() error {
	c.calls++
	if c.calls > 2 {
		return context.Canceled
	}
	return nil
}

func TestCountryPrefixesClosedInputsCancellationAndNoPartialAcceptedResult(t *testing.T) {
	s := countryFixture(t, netip.MustParsePrefix("8.8.8.0/24"), true, fixtureRecord())
	for _, codes := range [][]string{nil, {}, {"US", "CN"}, {"US", "US"}, {"us"}, {"U;"}, {"ZZ"}, {"USA"}} {
		got, err := s.CountryPrefixes(context.Background(), codes, 10)
		if err == nil || !reflect.DeepEqual(got, CountryNetworkExport{}) {
			t.Fatal("accepted malformed selection or partial", codes, got, err)
		}
	}
	for _, limit := range []int{0, -1, maxCountryNetworks + 1} {
		got, err := s.CountryPrefixes(context.Background(), []string{"US"}, limit)
		if err == nil || !reflect.DeepEqual(got, CountryNetworkExport{}) {
			t.Fatal("accepted invalid budget")
		}
	}
	if _, err := s.CountryPrefixes(nil, []string{"US"}, 10); err == nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.CountryPrefixes(ctx, []string{"US"}, 10); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, CountryNetworkExport{}) {
		t.Fatal("pre-cancel accepted")
	}
	if got, err := s.CountryPrefixes(&countryCancelContext{Context: context.Background()}, []string{"US"}, 10); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, CountryNetworkExport{}) {
		t.Fatal("mid-stream partial accepted", got, err)
	}
	var absent *Snapshot
	if _, err := absent.CountryPrefixes(context.Background(), []string{"US"}, 10); err == nil {
		t.Fatal("nil database")
	}
	s.Close()
	if _, err := s.CountryPrefixes(context.Background(), []string{"US"}, 10); err == nil {
		t.Fatal("closed database")
	}
}

func TestCountryPrefixesRejectMalformedRecordEvenIfCountryNotSelected(t *testing.T) {
	for _, code := range []string{"U;", "uS", "USA"} {
		row := fixtureRecord()
		row["country"].(map[string]any)["iso_code"] = code
		s := countryFixture(t, netip.MustParsePrefix("8.8.8.0/24"), false, row)
		got, err := s.CountryPrefixes(context.Background(), []string{"CN"}, 100)
		if err == nil || !reflect.DeepEqual(got, CountryNetworkExport{}) {
			t.Fatal("malformed country silently omitted", code, got, err)
		}
	}
}

func TestCountryPrefixesOutputBudgetReturnsNoPartialExport(t *testing.T) {
	s := countryFixture(t, netip.MustParsePrefix("0.0.0.0/1"), false, fixtureRecord())
	got, err := s.CountryPrefixes(context.Background(), []string{"US"}, 1)
	if err == nil || !reflect.DeepEqual(got, CountryNetworkExport{}) {
		t.Fatal("over-budget partial export", got, err)
	}
}

func TestCountryAppendRefusesOverlapAndOnlyMergesSameCountrySiblings(t *testing.T) {
	x := CountryNetwork{Prefix: netip.MustParsePrefix("8.8.8.0/25"), CountryCode: "US"}
	y := CountryNetwork{Prefix: netip.MustParsePrefix("8.8.8.128/25"), CountryCode: "CN"}
	got, err := countryAppend([]CountryNetwork{x}, y)
	if err != nil || len(got) != 2 {
		t.Fatal("merged different countries")
	}
	y.CountryCode = "US"
	got, err = countryAppend([]CountryNetwork{x}, y)
	if err != nil || len(got) != 1 || got[0].Prefix.String() != "8.8.8.0/24" {
		t.Fatal("complete siblings not merged", got, err)
	}
	for _, bad := range []CountryNetwork{x, {Prefix: netip.MustParsePrefix("8.8.8.0/24"), CountryCode: "US"}, {Prefix: netip.MustParsePrefix("8.8.7.0/24"), CountryCode: "US"}} {
		if result, err := countryAppend([]CountryNetwork{x}, bad); err == nil || result != nil {
			t.Fatal("overlap/duplicate/order accepted")
		}
	}
}
