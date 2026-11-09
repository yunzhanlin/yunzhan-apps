package geodata

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

// CountryNetwork is data, never a directive, filename or executable. Consumers
// must bind an export's database identity to their own verified installation.
type CountryNetwork struct {
	Prefix      netip.Prefix
	CountryCode string
}

type CountryNetworkExport struct {
	ManifestSHA256 string
	DatabaseSHA256 string
	RecordsVisited int
	Networks       []CountryNetwork
}

const maxCountryNetworks = 1 << 20
const maxCountryNetworkVisits = 1 << 24

func countryCodeValid(code string) bool {
	return len(code) == 2 && code != "ZZ" && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z'
}

func countryPrefixChildren(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bit := prefix.Bits()
	if prefix.Addr().Is4() {
		right := prefix.Addr().As4()
		right[bit/8] |= 1 << uint(7-bit%8)
		return netip.PrefixFrom(prefix.Addr(), bit+1), netip.PrefixFrom(netip.AddrFrom4(right), bit+1)
	}
	right := prefix.Addr().As16()
	right[bit/8] |= 1 << uint(7-bit%8)
	return netip.PrefixFrom(prefix.Addr(), bit+1), netip.PrefixFrom(netip.AddrFrom16(right), bit+1)
}

// Subtraction never widens a provider prefix. Keep the same conservative
// special-use exclusions as Lookup, including transition and documentation IPs.
func countrySubtract(prefix, blocked netip.Prefix, result *[]netip.Prefix) {
	if prefix.Addr().BitLen() != blocked.Addr().BitLen() || !prefix.Overlaps(blocked) {
		*result = append(*result, prefix)
		return
	}
	if blocked.Bits() <= prefix.Bits() {
		return
	}
	left, right := countryPrefixChildren(prefix)
	countrySubtract(left, blocked, result)
	countrySubtract(right, blocked, result)
}

func countryPublicPrefixes(prefix netip.Prefix) []netip.Prefix {
	parts := []netip.Prefix{prefix}
	for _, blocked := range excluded {
		if prefix.Addr().BitLen() != blocked.Addr().BitLen() || !prefix.Overlaps(blocked) {
			continue
		}
		next := make([]netip.Prefix, 0, len(parts))
		for _, part := range parts {
			countrySubtract(part, blocked, &next)
		}
		parts = next
		if len(parts) == 0 {
			return nil
		}
	}
	return parts
}

// MMDB traversal is ordered within each address family. Merge only complete
// same-country sibling prefixes, not arbitrary adjacent ranges or holes left
// by special-use exclusions. There are no overlaps or duplicate aliases.
func countryAppend(stack []CountryNetwork, entry CountryNetwork) ([]CountryNetwork, error) {
	for len(stack) > 0 {
		previous := stack[len(stack)-1]
		if previous.Prefix.Overlaps(entry.Prefix) || previous.Prefix.Addr().Compare(entry.Prefix.Addr()) >= 0 {
			return nil, errors.New("地域网络顺序、重叠或地址族别名不受信")
		}
		bits := entry.Prefix.Bits()
		if bits == 0 || previous.CountryCode != entry.CountryCode || previous.Prefix.Bits() != bits {
			break
		}
		parent := netip.PrefixFrom(entry.Prefix.Addr(), bits-1).Masked()
		if netip.PrefixFrom(previous.Prefix.Addr(), bits-1).Masked() != parent {
			break
		}
		stack = stack[:len(stack)-1]
		entry.Prefix = parent
	}
	return append(stack, entry), nil
}

// CountryPrefixes performs a complete read-only traversal of an already
// signature/hash/structure-verified immutable snapshot. Run it in a separately
// bounded worker, not an HTTP handler. Cancellation, a malformed record,
// incomplete traversal or either budget returns NO partial accepted export.
// Codes are canonical two-letter provider labels, not a claim about political
// boundaries or the accuracy/completeness of geolocation. Zero matches remain
// explicit data; callers must not claim that a zero-coverage rule blocks users.
func (s *Snapshot) CountryPrefixes(ctx context.Context, countries []string, limit int) (CountryNetworkExport, error) {
	var empty CountryNetworkExport
	if ctx == nil || len(countries) < 1 || len(countries) > 32 || limit < 1 || limit > maxCountryNetworks {
		return empty, errors.New("地域导出上下文、选择或容量无效")
	}
	wanted := make(map[string]string, len(countries))
	for i, code := range countries {
		if !countryCodeValid(code) || i > 0 && countries[i-1] >= code {
			return empty, errors.New("地域选择必须为有序唯一的规范代码")
		}
		// A short exported label must not keep an entire MMDB buffer alive.
		wanted[code] = strings.Clone(code)
	}
	return s.countryPrefixes(ctx, wanted, false, limit)
}

// AllCountryPrefixes is an OFFLINE PUBLISHER operation, not an HTTP lookup or
// a request-supplied verification shortcut. It retains the same full-tree and
// result budgets, conservative exclusions and zero-partial-result contract.
func (s *Snapshot) AllCountryPrefixes(ctx context.Context, limit int) (CountryNetworkExport, error) {
	if ctx == nil || limit < 1 || limit > maxCountryNetworks {
		return CountryNetworkExport{}, errors.New("完整地域导出上下文或容量无效")
	}
	return s.countryPrefixes(ctx, map[string]string{}, true, limit)
}

func (s *Snapshot) countryPrefixes(ctx context.Context, wanted map[string]string, all bool, limit int) (CountryNetworkExport, error) {
	var empty CountryNetworkExport
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if s == nil {
		return empty, errors.New("地域数据库尚不可用")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.reader == nil || !s.authority.verified {
		return empty, errors.New("地域数据库已关闭或未独立核验")
	}
	stacks := [2][]CountryNetwork{}
	visited := 0
	for result := range s.reader.Networks() {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		visited++
		if visited > maxCountryNetworkVisits || result.Err() != nil {
			return empty, errors.New("地域网络遍历异常或超过固定容量")
		}
		prefix := result.Prefix()
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return empty, errors.New("地域网络前缀不是规范地址族")
		}
		var row struct {
			Country struct {
				ISO string `maxminddb:"iso_code,maxsize:2"`
			} `maxminddb:"country"`
		}
		if result.Decode(&row) != nil {
			return empty, errors.New("地域国家字段无法完整读取")
		}
		code := row.Country.ISO
		if code == "" || code == "ZZ" {
			continue
		}
		if !countryCodeValid(code) {
			return empty, errors.New("地域国家字段不是规范代码")
		}
		selected, wantedCountry := wanted[code]
		if !wantedCountry && all {
			selected = strings.Clone(code)
			wanted[code] = selected
			wantedCountry = true
		}
		if !wantedCountry {
			continue
		}
		family := 1
		if prefix.Addr().Is4() {
			family = 0
		}
		for _, part := range countryPublicPrefixes(prefix) {
			var err error
			stacks[family], err = countryAppend(stacks[family], CountryNetwork{Prefix: part, CountryCode: selected})
			if err != nil {
				return empty, err
			}
			if len(stacks[0])+len(stacks[1]) > limit {
				return empty, errors.New("地域网络导出超过固定容量；未接受部分覆盖")
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	entries := make([]CountryNetwork, 0, len(stacks[0])+len(stacks[1]))
	entries = append(entries, stacks[0]...)
	entries = append(entries, stacks[1]...)
	return CountryNetworkExport{ManifestSHA256: s.authority.digest, DatabaseSHA256: s.authority.manifest.SHA256, RecordsVisited: visited, Networks: entries}, nil
}
