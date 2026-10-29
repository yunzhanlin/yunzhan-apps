package geodata

import (
	"bytes"
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// Independently encoded multi-country IPv4/IPv6 MMDB. Synthetic only; signed
// with the test authority, never the publisher key or installed data authority.
func countryMixedFixture(t *testing.T) *Snapshot {
	t.Helper()
	type pointer struct {
		node, record int
		leaf         bool
		present      bool
	}
	nodes := [][2]pointer{{}}
	records := [][]byte{}
	for _, item := range []struct{ prefix, code string }{{"8.8.8.0/25", "US"}, {"8.8.8.128/25", "CN"}, {"8.8.9.0/24", "US"}, {"9.9.9.0/24", "CH"}, {"2606:4700::/33", "AU"}, {"2606:4700:8000::/33", "US"}} {
		prefix := netip.MustParsePrefix(item.prefix)
		address := prefix.Addr().AsSlice()
		bits := prefix.Bits()
		if prefix.Addr().Is4() {
			address = make([]byte, 16)
			copy(address[12:], prefix.Addr().AsSlice())
			bits += 96
		}
		row := fixtureRecord()
		row["country"] = map[string]any{"iso_code": item.code, "names": map[string]any{"en": "Synthetic country"}}
		record := len(records)
		records = append(records, mmdbValue(row))
		current := 0
		for bit := 0; bit < bits; bit++ {
			side := int((address[bit/8] >> uint(7-bit%8)) & 1)
			edge := nodes[current][side]
			if bit == bits-1 {
				if edge.present {
					t.Fatal("overlapping fixture leaf")
				}
				nodes[current][side] = pointer{record: record, leaf: true, present: true}
				break
			}
			if edge.leaf {
				t.Fatal("overlapping fixture ancestor")
			}
			if !edge.present {
				edge = pointer{node: len(nodes), present: true}
				nodes = append(nodes, [2]pointer{})
				nodes[current][side] = edge
			}
			current = edge.node
		}
	}
	data := []byte{}
	offsets := make([]uint32, len(records))
	for i, record := range records {
		offsets[i] = uint32(len(data))
		data = append(data, record...)
	}
	tree := make([]byte, len(nodes)*6)
	for i, pair := range nodes {
		for side, edge := range pair {
			value := uint32(len(nodes))
			if edge.present {
				if edge.leaf {
					value = uint32(len(nodes)+16) + offsets[edge.record]
				} else {
					value = uint32(edge.node)
				}
			}
			at := i*6 + side*3
			tree[at] = byte(value >> 16)
			tree[at+1] = byte(value >> 8)
			tree[at+2] = byte(value)
		}
	}
	raw := append(tree, make([]byte, 16)...)
	raw = append(raw, data...)
	raw = append(raw, []byte("\xAB\xCD\xEFMaxMind.com")...)
	metadata := map[string]any{"node_count": uint32(len(nodes)), "record_size": uint32(24), "ip_version": uint32(6), "database_type": "DBIP-City-Lite", "binary_format_major_version": uint32(2), "binary_format_minor_version": uint32(0), "build_epoch": uint64(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix()), "languages": []any{"en"}, "description": map[string]any{"en": "Mixed country fixture"}}
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

func TestCountryShardsMixedCountryBoundariesMatchIndependentSelectionAndLookup(t *testing.T) {
	s := countryMixedFixture(t)
	out, err := s.CountryShards(context.Background())
	if err != nil || len(out.Shards) != 4 || out.Networks != 6 {
		t.Fatal(out, err)
	}
	codes := []string{}
	all := []CountryNetwork{}
	for _, shard := range out.Shards {
		codes = append(codes, shard.Code)
		selected, err := s.CountryPrefixes(context.Background(), []string{shard.Code}, 32)
		if err != nil || !reflect.DeepEqual(selected, shard.Data) {
			t.Fatal("cross-country shard differs from independent selected traversal", shard.Code, err)
		}
		var encoded bytes.Buffer
		written, err := EncodeCountryCIDR(context.Background(), shard.Data, &encoded)
		if err != nil {
			t.Fatal(err)
		}
		read, err := ValidateCountryCIDR(context.Background(), bytes.NewReader(encoded.Bytes()))
		if err != nil || !reflect.DeepEqual(written, read) || len(read.Countries) != 1 || read.Countries[0].Code != shard.Code {
			t.Fatal("cross-country codec changed identity", shard.Code, err)
		}
		for _, row := range shard.Data.Networks {
			for _, prior := range all {
				if prior.Prefix.Overlaps(row.Prefix) {
					t.Fatal("different countries overlap", prior, row)
				}
			}
			all = append(all, row)
		}
	}
	if !reflect.DeepEqual(codes, []string{"AU", "CH", "CN", "US"}) {
		t.Fatal(codes)
	}
	for ip, want := range map[string]string{"8.8.8.1": "US", "8.8.8.200": "CN", "8.8.9.2": "US", "9.9.9.9": "CH", "2606:4700::1": "AU", "2606:4700:8000::1": "US"} {
		location := s.Lookup(ip)
		if location.Status != "located" || location.CountryCode != want {
			t.Fatal("independent direct lookup differs", ip, location)
		}
		matches := []string{}
		for _, row := range all {
			if row.Prefix.Contains(netip.MustParseAddr(ip)) {
				matches = append(matches, row.CountryCode)
			}
		}
		if !reflect.DeepEqual(matches, []string{want}) {
			t.Fatal("shard lost/crossed real address boundary", ip, matches, want)
		}
	}
}
