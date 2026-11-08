package geodata

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	hashio "hash"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Flat publisher-generated data is independently validated before a consumer
// may use it. This codec grants NO signature/install/configuration authority.
// A consumer must bind these exact bytes and both parent digests to its own
// original-key authenticated derived-data manifest and immutable lifecycle.
const MaxCountryCIDRBytes int64 = 64 << 20

const countryCIDRHeader = "# panel-country-networks-v1\n"

type CountryCIDRCount struct {
	Code     string `json:"code"`
	Networks int    `json:"networks"`
}

type CountryCIDRMetadata struct {
	Bytes                int64              `json:"bytes"`
	SHA256               string             `json:"sha256"`
	ParentManifestSHA256 string             `json:"parent_manifest_sha256"`
	ParentDatabaseSHA256 string             `json:"parent_database_sha256"`
	Networks             int                `json:"networks"`
	Countries            []CountryCIDRCount `json:"countries"`
}

type countryCIDRState struct {
	previous CountryNetwork
	count    int
	codes    map[string]int
}

func (s *countryCIDRState) append(row CountryNetwork) error {
	p := row.Prefix
	if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" || !countryCodeValid(row.CountryCode) {
		return errors.New("地域平面数据包含非规范前缀或国家代码")
	}
	for _, blocked := range excluded {
		if p.Overlaps(blocked) {
			return errors.New("地域平面数据包含非公网或特殊用途网段")
		}
	}
	if s.count >= maxCountryNetworks {
		return errors.New("地域平面数据网段数超过固定容量")
	}
	if s.count > 0 {
		previous := s.previous
		if previous.Prefix.Addr().Compare(p.Addr()) >= 0 || previous.Prefix.Overlaps(p) {
			return errors.New("地域平面数据次序、重复或重叠异常")
		}
		if previous.CountryCode == row.CountryCode && previous.Prefix.Addr().BitLen() == p.Addr().BitLen() && previous.Prefix.Bits() == p.Bits() && p.Bits() > 0 && netip.PrefixFrom(previous.Prefix.Addr(), p.Bits()-1).Masked() == netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked() {
			return errors.New("地域平面数据包含未规范合并的同国相邻网段")
		}
	}
	s.previous = row
	s.count++
	if count, exists := s.codes[row.CountryCode]; exists {
		s.codes[row.CountryCode] = count + 1
	} else {
		s.codes[strings.Clone(row.CountryCode)] = 1
	}
	return nil
}

func (s *countryCIDRState) metadata(bytes int64, hash, manifest, database string) CountryCIDRMetadata {
	countries := make([]CountryCIDRCount, 0, len(s.codes))
	for code, count := range s.codes {
		countries = append(countries, CountryCIDRCount{code, count})
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Code < countries[j].Code })
	return CountryCIDRMetadata{bytes, hash, strings.Clone(manifest), strings.Clone(database), s.count, countries}
}

type countryCIDRBytes struct{ count int64 }

func (c *countryCIDRBytes) Write(b []byte) (int, error) {
	if int64(len(b)) > MaxCountryCIDRBytes-c.count {
		return 0, errors.New("地域平面数据字节数超过固定容量")
	}
	c.count += int64(len(b))
	return len(b), nil
}

// EncodeCountryCIDR validates the ENTIRE input before writing. Write failure or
// cancellation still returns zero accepted metadata: the publisher must use an
// exclusive staging artifact, never publish/sign partial output in place.
func EncodeCountryCIDR(ctx context.Context, data CountryNetworkExport, output io.Writer) (CountryCIDRMetadata, error) {
	var empty CountryCIDRMetadata
	if ctx == nil || output == nil || !digestPattern.MatchString(data.ManifestSHA256) || !digestPattern.MatchString(data.DatabaseSHA256) || len(data.Networks) == 0 || len(data.Networks) > maxCountryNetworks || data.RecordsVisited < 1 || data.RecordsVisited > maxCountryNetworkVisits {
		return empty, errors.New("地域平面导出上下文、来源或容量无效")
	}
	state := countryCIDRState{codes: map[string]int{}}
	for _, row := range data.Networks {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if err := state.append(row); err != nil {
			return empty, err
		}
	}
	hash, size := sha256.New(), &countryCIDRBytes{}
	w := io.MultiWriter(size, output, hash)
	if _, err := fmt.Fprintf(w, countryCIDRHeader+"# parent-manifest-sha256: %s\n# parent-database-sha256: %s\n", data.ManifestSHA256, data.DatabaseSHA256); err != nil {
		return empty, err
	}
	for _, row := range data.Networks {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if _, err := fmt.Fprintf(w, "%s %s;\n", row.Prefix, row.CountryCode); err != nil {
			return empty, err
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return state.metadata(size.count, hex.EncodeToString(hash.Sum(nil)), data.ManifestSHA256, data.DatabaseSHA256), nil
}

// ValidateCountryCIDR streams a closed, bounded Nginx geo INCLUDE DATA format.
// It accepts no Nginx directives, variables, filenames, URLs or user commands.
// It does not infer signed authority from the two provenance comment fields.
func ValidateCountryCIDR(ctx context.Context, input io.Reader) (CountryCIDRMetadata, error) {
	var empty CountryCIDRMetadata
	cursor, err := newCountryCIDRCursor(ctx, input)
	if err != nil {
		return empty, err
	}
	for {
		_, err := cursor.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return empty, err
		}
	}
	return cursor.result()
}

// Private streaming cursor shared by the single-file verifier and the joint
// signed-selection verifier. No cursor row is public acceptance authority.
type countryCIDRCursor struct {
	ctx     context.Context
	reader  *bufio.Reader
	limited *io.LimitedReader
	size    *countryCIDRBytes
	hash    hashio.Hash
	state   countryCIDRState
	parents []string
	done    bool
}

func newCountryCIDRCursor(ctx context.Context, input io.Reader) (*countryCIDRCursor, error) {
	if ctx == nil || input == nil {
		return nil, errors.New("地域平面读取上下文或流缺失")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hash, size := sha256.New(), &countryCIDRBytes{}
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: MaxCountryCIDRBytes + 1}
	r := bufio.NewReaderSize(io.TeeReader(limited, io.MultiWriter(size, hash)), 256)
	c := &countryCIDRCursor{ctx: ctx, reader: r, limited: limited, size: size, hash: hash, state: countryCIDRState{codes: map[string]int{}}}
	first, err := c.line()
	if err != nil {
		return nil, err
	}
	if first != countryCIDRHeader {
		return nil, errors.New("地域平面数据协议不符")
	}
	for _, prefix := range []string{"# parent-manifest-sha256: ", "# parent-database-sha256: "} {
		value, err := c.line()
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(value, prefix) {
			return nil, errors.New("地域平面数据来源字段缺失")
		}
		digest := strings.TrimSuffix(strings.TrimPrefix(value, prefix), "\n")
		if !digestPattern.MatchString(digest) || value != prefix+digest+"\n" {
			return nil, errors.New("地域平面数据来源摘要非规范")
		}
		c.parents = append(c.parents, digest)
	}
	return c, nil
}

func (c *countryCIDRCursor) line() (string, error) {
	if err := c.ctx.Err(); err != nil {
		return "", err
	}
	b, err := c.reader.ReadSlice('\n')
	if err != nil {
		if c.ctx.Err() != nil {
			return "", c.ctx.Err()
		}
		if errors.Is(err, io.EOF) && len(b) == 0 {
			return "", io.EOF
		}
		return "", errors.New("地域平面数据行缺失、超长或流未完整结束")
	}
	return string(b), nil
}

func (c *countryCIDRCursor) next() (CountryNetwork, error) {
	var empty CountryNetwork
	if err := c.ctx.Err(); err != nil {
		return empty, err
	}
	if c.done {
		return empty, io.EOF
	}
	value, err := c.line()
	if errors.Is(err, io.EOF) {
		c.done = true
		return empty, io.EOF
	}
	if err != nil {
		return empty, err
	}
	prefix, code, found := strings.Cut(value, " ")
	p, err := netip.ParsePrefix(prefix)
	if !found || err != nil || prefix != p.String() || len(code) != 4 || code[2:] != ";\n" {
		return empty, errors.New("地域平面数据只能包含规范前缀与两字母代码")
	}
	row := CountryNetwork{p, code[:2]}
	if err := c.state.append(row); err != nil {
		return empty, err
	}
	return row, nil
}

func (c *countryCIDRCursor) result() (CountryCIDRMetadata, error) {
	var empty CountryCIDRMetadata
	if !c.done || c.state.count == 0 || c.size.count > MaxCountryCIDRBytes || c.limited.N <= 0 {
		return empty, errors.New("地域平面数据没有覆盖或超过固定预算")
	}
	if err := c.ctx.Err(); err != nil {
		return empty, err
	}
	return c.state.metadata(c.size.count, hex.EncodeToString(c.hash.Sum(nil)), c.parents[0], c.parents[1]), nil
}
