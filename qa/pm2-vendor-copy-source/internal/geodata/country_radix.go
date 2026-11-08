package geodata

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"net/netip"
)

// Sorted, non-overlapping canonical prefixes need only their predecessor to
// count newly introduced radix nodes: an earlier address cannot share a longer
// prefix than the immediate predecessor. This keeps the complete signed merge
// O(selected countries) in memory, even at the original million-network bound.
// Nginx uses uncompressed bit nodes for geo CIDR trees:
// https://github.com/nginx/nginx/blob/release-1.24.0/src/core/ngx_radix_tree.c
func countryRadixNodeDelta(previous, next netip.Prefix) (uint64, error) {
	valid := func(p netip.Prefix) bool {
		return p.IsValid() && p == p.Masked() && !p.Addr().Is4In6() && p.Addr().Zone() == ""
	}
	if !valid(next) || previous.IsValid() && (!valid(previous) || previous.Addr().Compare(next.Addr()) >= 0 || previous.Overlaps(next)) {
		return 0, errors.New("country radix capacity requires ordered non-overlapping canonical prefixes")
	}
	if !previous.IsValid() || previous.Addr().BitLen() != next.Addr().BitLen() {
		return uint64(next.Bits()), nil
	}
	common := 0
	if next.Addr().Is4() {
		a, b := previous.Addr().As4(), next.Addr().As4()
		common = bits.LeadingZeros32(binary.BigEndian.Uint32(a[:]) ^ binary.BigEndian.Uint32(b[:]))
	} else {
		a, b := previous.Addr().As16(), next.Addr().As16()
		high := binary.BigEndian.Uint64(a[:8]) ^ binary.BigEndian.Uint64(b[:8])
		common = bits.LeadingZeros64(high)
		if high == 0 {
			common += bits.LeadingZeros64(binary.BigEndian.Uint64(a[8:]) ^ binary.BigEndian.Uint64(b[8:]))
		}
	}
	if common >= previous.Bits() || common >= next.Bits() {
		return 0, errors.New("country radix capacity cannot adopt nested prefixes")
	}
	return uint64(next.Bits() - common), nil
}
