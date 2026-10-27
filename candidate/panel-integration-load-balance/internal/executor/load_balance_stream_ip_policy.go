package executor

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"local/panel/internal/loadbalancestream"
)

// Decode the fixed manager's typed a(iayu) value, not human-formatted CIDRs
// or arbitrary JSON. This only checks the manager's policy metadata; actual
// attached filters and native positive/negative traffic remain mandatory.
func streamServiceIPPrefixes(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return nil, loadbalancestream.ErrService
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 || fields[0] != "a(iayu)" {
		return nil, loadbalancestream.ErrService
	}
	read := func(v string, maximum uint64) (uint64, bool) {
		n, err := strconv.ParseUint(v, 10, 32)
		return n, err == nil && n <= maximum && strconv.FormatUint(n, 10) == v
	}
	count, ok := read(fields[1], 2*loadbalancestream.MaxEntries*16+2)
	if !ok || count == 0 {
		return nil, loadbalancestream.ErrService
	}
	seen := map[string]bool{}
	out := make([]string, 0, count)
	pos := 2
	for n := uint64(0); n < count; n++ {
		if pos+2 > len(fields) {
			return nil, loadbalancestream.ErrService
		}
		family, fOK := read(fields[pos], 10)
		size, sOK := read(fields[pos+1], 16)
		pos += 2
		if !fOK || !sOK || family != 2 && family != 10 || family == 2 && size != 4 || family == 10 && size != 16 || pos+int(size)+1 > len(fields) {
			return nil, loadbalancestream.ErrService
		}
		var data [16]byte
		for i := uint64(0); i < size; i++ {
			v, ok := read(fields[pos], 255)
			if !ok {
				return nil, loadbalancestream.ErrService
			}
			data[i] = byte(v)
			pos++
		}
		bits, ok := read(fields[pos], size*8)
		pos++
		if !ok {
			return nil, loadbalancestream.ErrService
		}
		var address netip.Addr
		if family == 2 {
			address = netip.AddrFrom4([4]byte(data[:4]))
		} else {
			address = netip.AddrFrom16(data)
			if address.Is4In6() {
				return nil, loadbalancestream.ErrService
			}
		}
		prefix := netip.PrefixFrom(address, int(bits))
		key := prefix.String()
		if prefix != prefix.Masked() || seen[key] {
			return nil, loadbalancestream.ErrService
		}
		seen[key] = true
		out = append(out, key)
	}
	if pos != len(fields) {
		return nil, loadbalancestream.ErrService
	}
	slices.Sort(out)
	return out, nil
}

func streamServiceIPPolicyMatches(allow, deny []byte, expected []string) bool {
	a, e1 := streamServiceIPPrefixes(allow)
	d, e2 := streamServiceIPPrefixes(deny)
	want := append([]string(nil), expected...)
	slices.Sort(want)
	if e1 != nil || e2 != nil || len(want) < 2 || !slices.Equal(a, want) || !slices.Equal(d, []string{"0.0.0.0/0", "::/0"}) {
		return false
	}
	for i, value := range want {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value || i > 0 && want[i-1] == value {
			return false
		}
	}
	return true
}
