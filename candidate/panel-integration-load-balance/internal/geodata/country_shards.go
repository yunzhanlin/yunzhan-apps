package geodata

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// A PUBLISHER may retain a bounded multi-country inventory, but EVERY shard
// still has the ORIGINAL one-million-network and 64MiB per-file limits. This
// aggregate is not a panel activation/download budget or a request option.
const maxCountryPublishNetworks = 4 << 20

type CountryShard struct {
	Code string
	Data CountryNetworkExport
}

type CountryShardExport struct {
	ManifestSHA256 string
	DatabaseSHA256 string
	RecordsVisited int
	Networks       int
	Shards         []CountryShard
}

func countryShardBudget(total, country int) error {
	if total < country || country < 1 || country > maxCountryNetworks || total > maxCountryPublishNetworks {
		return errors.New("国家分片或发布端总容量超限；未接受部分数据")
	}
	return nil
}

// CountryShards traverses the fully authenticated immutable MMDB ONCE. The
// result is for an offline publisher, not a panel HTTP handler. Consumers may
// subsequently pull only the signed country shards their policies require.
func (s *Snapshot) CountryShards(ctx context.Context) (CountryShardExport, error) {
	var empty CountryShardExport
	if ctx == nil || s == nil {
		return empty, errors.New("国家分片上下文或数据库缺失")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.reader == nil || !s.authority.verified {
		return empty, errors.New("国家分片数据库已关闭或未核验")
	}
	type stacks struct {
		code     string
		families [2][]CountryNetwork
	}
	groups := map[string]*stacks{}
	total, visited := 0, 0
	for result := range s.reader.Networks() {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		visited++
		if visited > maxCountryNetworkVisits || result.Err() != nil {
			return empty, errors.New("国家分片遍历不完整或超过原固定容量")
		}
		prefix := result.Prefix()
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return empty, errors.New("国家分片前缀不是规范地址族")
		}
		var row struct {
			Country struct {
				ISO string `maxminddb:"iso_code,maxsize:2"`
			} `maxminddb:"country"`
		}
		if result.Decode(&row) != nil {
			return empty, errors.New("国家分片字段无法完整读取")
		}
		code := row.Country.ISO
		if code == "" || code == "ZZ" {
			continue
		}
		if !countryCodeValid(code) {
			return empty, errors.New("国家分片代码非规范")
		}
		parts := countryPublicPrefixes(prefix)
		if len(parts) == 0 {
			continue
		}
		group, exists := groups[code]
		if !exists {
			code = strings.Clone(code)
			group = &stacks{code: code}
			groups[code] = group
		}
		code = group.code
		family := 1
		if prefix.Addr().Is4() {
			family = 0
		}
		for _, part := range parts {
			before := len(group.families[family])
			var err error
			group.families[family], err = countryAppend(group.families[family], CountryNetwork{part, code})
			if err != nil {
				return empty, err
			}
			total += len(group.families[family]) - before
			if err := countryShardBudget(total, len(group.families[0])+len(group.families[1])); err != nil {
				return empty, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	codes := make([]string, 0, len(groups))
	for code := range groups {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	out := CountryShardExport{ManifestSHA256: s.authority.digest, DatabaseSHA256: s.authority.manifest.SHA256, RecordsVisited: visited, Networks: total, Shards: make([]CountryShard, 0, len(codes))}
	for _, code := range codes {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		group := groups[code]
		// Release the old per-family buffers as each result is combined. Do
		// not keep a second complete multi-country inventory alive.
		networks := append(group.families[0], group.families[1]...)
		out.Shards = append(out.Shards, CountryShard{code, CountryNetworkExport{out.ManifestSHA256, out.DatabaseSHA256, visited, networks}})
		delete(groups, code)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return out, nil
}
