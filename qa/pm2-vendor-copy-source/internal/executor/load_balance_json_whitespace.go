package executor

import "encoding/binary"

// A history record may contain JSON's four ASCII whitespace bytes. Skip the
// common long space padding eight bytes at a time, without changing the raw
// record, its complete read/digest, limits, ownership checks or decoder. Every
// other suffix byte (including Unicode whitespace) still reaches the strict
// original JSON decoder. There is no retained-body or result cache.
func trimLoadBalanceJSONTrailingWhitespace(raw []byte) []byte {
	end := len(raw)
	for end > 0 {
		if end >= 8 && binary.LittleEndian.Uint64(raw[end-8:end]) == 0x2020202020202020 {
			end -= 8
			continue
		}
		switch raw[end-1] {
		case ' ', '\t', '\r', '\n':
			end--
		default:
			return raw[:end]
		}
	}
	return raw[:0]
}
