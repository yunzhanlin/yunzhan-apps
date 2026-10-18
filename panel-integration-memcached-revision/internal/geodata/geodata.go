// Package geodata reads signed, offline DB-IP City Lite snapshots. It never
// contacts a geolocation service, executes commands, or accepts caller URLs.
package geodata

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

const Channel = "dbip-city-lite-v1"
const SignatureDomain = "yunzhan-geodata-city-v1\n"
const LicenseURL = "https://creativecommons.org/licenses/by/4.0/"
const AttributionURL = "https://db-ip.com/"
const Attribution = "IP Geolocation by DB-IP"
const MaxCompressedBytes = 80 << 20
const MaxDatabaseBytes = 160 << 20
const maxManifestBytes = 4096

// Manifest contains data identity and license provenance only. It cannot
// select a key, destination, executable, privilege, or arbitrary provider.
type Manifest struct {
	Format           int    `json:"format"`
	Channel          string `json:"channel"`
	Release          string `json:"release"`
	BuildEpoch       uint64 `json:"build_epoch"`
	CompressedBytes  int64  `json:"compressed_bytes"`
	CompressedSHA256 string `json:"compressed_sha256"`
	Bytes            int64  `json:"bytes"`
	SHA256           string `json:"sha256"`
	Source           string `json:"source"`
	License          string `json:"license"`
	AttributionURL   string `json:"attribution_url"`
}

// Authority is opaque and detached from caller buffers. The privileged
// receiver must verify using its own pinned key, not a key in an API request.
type Authority struct {
	manifest Manifest
	digest   string
	verified bool
}

func (a Authority) Manifest() Manifest { return a.manifest }
func (a Authority) SHA256() string     { return a.digest }

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var releasePattern = regexp.MustCompile(`^20[2-9][0-9]-(0[1-9]|1[0-2])$`)

// Flat, exact-spelling JSON: reject duplicates, case aliases, null, nested
// containers, extra values and unknown fields before Go's typed decoder.
func decodeManifest(raw []byte, out *Manifest) error {
	if !utf8.Valid(raw) {
		return errors.New("地理数据清单 UTF-8 无效")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("地理数据清单须为对象")
	}
	allowed := map[string]bool{"format": true, "channel": true, "release": true, "build_epoch": true, "compressed_bytes": true, "compressed_sha256": true, "bytes": true, "sha256": true, "source": true, "license": true, "attribution_url": true}
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return errors.New("地理数据清单含重复、未知或非规范字段")
		}
		seen[name] = true
		value, err := dec.Token()
		if _, nested := value.(json.Delim); err != nil || value == nil || nested {
			return errors.New("地理数据清单字段无效")
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return errors.New("地理数据清单不完整")
	}
	if _, err = dec.Token(); err != io.EOF {
		return errors.New("地理数据清单含多余值")
	}
	return json.Unmarshal(raw, out)
}

func VerifyManifest(raw, signature []byte, public ed25519.PublicKey, now time.Time, previous *Authority) (Authority, error) {
	var empty Authority
	if len(raw) == 0 || len(raw) > maxManifestBytes || len(signature) > 128 || len(public) != ed25519.PublicKeySize || now.Year() < 2026 {
		return empty, errors.New("地理数据验签输入或时钟无效")
	}
	raw = bytes.Clone(raw)
	text := strings.TrimSuffix(string(signature), "\n")
	sig, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != text || !ed25519.Verify(public, append([]byte(SignatureDomain), raw...), sig) {
		return empty, errors.New("地理数据签名无效")
	}
	var m Manifest
	if decodeManifest(raw, &m) != nil || m.Format != 1 || m.Channel != Channel || !releasePattern.MatchString(m.Release) || !digestPattern.MatchString(m.SHA256) || !digestPattern.MatchString(m.CompressedSHA256) || m.Bytes < 1 || m.Bytes > MaxDatabaseBytes || m.CompressedBytes < 1 || m.CompressedBytes > MaxCompressedBytes || m.License != LicenseURL || m.AttributionURL != AttributionURL || m.Source != "https://download.db-ip.com/free/dbip-city-lite-"+m.Release+".mmdb.gz" {
		return empty, errors.New("地理数据格式、预算、来源或许可不符")
	}
	month, err := time.Parse("2006-01", m.Release)
	// Monthly vendors may generate a release shortly before its first day.
	if err != nil || m.BuildEpoch > uint64(math.MaxInt64) || month.After(time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)) {
		return empty, errors.New("地理数据月份无效或尚未发布")
	}
	built := time.Unix(int64(m.BuildEpoch), 0).UTC()
	if built.Before(month.AddDate(0, 0, -7)) || !built.Before(month.AddDate(0, 1, 7)) || built.After(now.Add(time.Hour)) {
		return empty, errors.New("地理数据构建时间与月份不符")
	}
	digest := hash(raw)
	if previous != nil && (!previous.verified || m.Release < previous.manifest.Release || m.Release == previous.manifest.Release && digest != previous.digest) {
		return empty, errors.New("地理数据回退或同月替换被拒绝；保留旧库")
	}
	return Authority{manifest: m, digest: digest, verified: true}, nil
}

func hash(raw []byte) string { value := sha256.Sum256(raw); return hex.EncodeToString(value[:]) }

type Metadata struct {
	Available      bool   `json:"available"`
	Release        string `json:"release"`
	BuildEpoch     uint64 `json:"build_epoch"`
	ManifestSHA256 string `json:"manifest_sha256"`
	SHA256         string `json:"sha256"`
	Stale          bool   `json:"stale"`
	License        string `json:"license"`
	Attribution    string `json:"attribution"`
	AttributionURL string `json:"attribution_url"`
}

// Snapshot owns its entire immutable byte buffer, not an mmap of a mutable
// live file. Close and lookups serialize so the reader never closes in use.
type Snapshot struct {
	mu        sync.RWMutex
	reader    *maxminddb.Reader
	authority Authority
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Allocate the signed exact size once: io.ReadAll's geometric growth would
// otherwise temporarily consume several times the database size on small VMs.
func readExact(ctx context.Context, reader io.Reader, size int64) ([]byte, error) {
	data := make([]byte, int(size)+1)
	n, err := io.ReadFull(contextReader{ctx, reader}, data)
	if n != int(size) || err != io.ErrUnexpectedEOF {
		return nil, errors.New("地理数据实际字节数不符或未完整读取")
	}
	return data[:n:n], nil
}

// Open is an installation/load operation, never a per-IP operation. It
// verifies exact compressed and expanded byte counts, both SHA-256 hashes,
// gzip checksum, the one-member boundary, metadata and the full MMDB tree.
// Full MMDB Verify is synchronous and has no hard CPU-time guarantee; callers
// should perform updates in a separately bounded worker, not an HTTP handler.
func Open(ctx context.Context, a Authority, compressed io.Reader) (*Snapshot, error) {
	return open(ctx, a, compressed, nil)
}

// OpenWithStructureVerifier keeps the same signature/size/hash/gzip/metadata
// checks, but delegates the complete tree check to a trusted internal adapter.
// The adapter receives only a read-only stream of the exact authenticated raw
// bytes. It MUST complete full verification or return an error. Production
// supplies the fixed resource-bounded same-program worker, never a callback,
// command, URL or verification flag deserialized from a panel request.
func OpenWithStructureVerifier(ctx context.Context, a Authority, compressed io.Reader, verify func(context.Context, Manifest, io.Reader) error) (*Snapshot, error) {
	if verify == nil {
		return nil, errors.New("地域数据完整结构核对器未配置")
	}
	return open(ctx, a, compressed, verify)
}

func open(ctx context.Context, a Authority, compressed io.Reader, verify func(context.Context, Manifest, io.Reader) error) (*Snapshot, error) {
	if !a.verified || compressed == nil || ctx == nil {
		return nil, errors.New("地理数据未独立验签")
	}
	m := a.manifest
	data, err := readExact(ctx, compressed, m.CompressedBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != m.CompressedBytes || hash(data) != m.CompressedSHA256 {
		return nil, errors.New("地理数据压缩包大小或摘要不符")
	}
	source := bytes.NewReader(data)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return nil, errors.New("地理数据不是有效 gzip")
	}
	reader.Multistream(false)
	database, readErr := readExact(ctx, reader, m.Bytes)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || int64(len(database)) != m.Bytes || source.Len() != 0 || hash(database) != m.SHA256 {
		return nil, errors.New("地理数据解压、单成员边界或摘要校验失败")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	db, err := maxminddb.OpenBytes(database, maxminddb.DisableStringCache())
	if err != nil {
		return nil, errors.New("地理数据库无法解析")
	}
	if !databaseIdentity(m, db) {
		_ = db.Close()
		return nil, errors.New("地理数据库类型、版本或构建身份不符")
	}
	if verify == nil {
		err = db.Verify()
	} else {
		err = verify(ctx, m, bytes.NewReader(database))
	}
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("地理数据库完整结构校验失败：%w", err)
	}
	if err = ctx.Err(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Snapshot{reader: db, authority: a}, nil
}

func databaseIdentity(m Manifest, db *maxminddb.Reader) bool {
	metadata := db.Metadata
	return metadata.DatabaseType == "DBIP-City-Lite" && metadata.IPVersion == 6 && metadata.BinaryFormatMajorVersion == 2 && metadata.BinaryFormatMinorVersion == 0 && uint64(metadata.BuildEpoch) == m.BuildEpoch && metadata.NodeCount <= uint(MaxDatabaseBytes/6)
}

func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reader == nil {
		return nil
	}
	err := s.reader.Close()
	s.reader = nil
	return err
}
func (s *Snapshot) Metadata(now time.Time) Metadata {
	if s == nil {
		return Metadata{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.authority.manifest
	return Metadata{Available: s.reader != nil, Release: m.Release, BuildEpoch: m.BuildEpoch, ManifestSHA256: s.authority.digest, SHA256: m.SHA256, Stale: now.Sub(time.Unix(int64(m.BuildEpoch), 0)) > 90*24*time.Hour, License: LicenseURL, Attribution: Attribution, AttributionURL: AttributionURL}
}

type Location struct {
	Status      string   `json:"status"`
	CountryCode string   `json:"country_code,omitempty"`
	Country     string   `json:"country,omitempty"`
	Region      string   `json:"region,omitempty"`
	City        string   `json:"city,omitempty"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
}
type localizedName struct {
	EN string `maxminddb:"en,maxsize:256"`
	ZH string `maxminddb:"zh-CN,maxsize:256"`
}
type record struct {
	Country struct {
		ISO   string        `maxminddb:"iso_code,maxsize:2"`
		Names localizedName `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names localizedName `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names localizedName `maxminddb:"names"`
	} `maxminddb:"subdivisions,maxsize:4"`
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

func locationName(n localizedName) (string, bool) {
	for _, text := range []string{n.EN, n.ZH} {
		if len(text) > 256 || !utf8.ValidString(text) {
			return "", false
		}
		for _, ch := range text {
			if unicode.IsControl(ch) {
				return "", false
			}
		}
	}
	if n.ZH != "" {
		return n.ZH, true
	}
	return n.EN, true
}

// Conservative exclusions: non-public and special-use addresses are never
// assigned a fabricated country. IPv4-mapped IPv6 is normalized first; zones
// and transition representations are not interpreted as a visitor location.
var excluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("5f00::/16"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fec0::/10"), netip.MustParsePrefix("ff00::/8"),
}

func (s *Snapshot) Lookup(text string) Location {
	ip, err := netip.ParseAddr(text)
	if err != nil || ip.Zone() != "" {
		return Location{Status: "invalid_ip"}
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() {
		return Location{Status: "non_public"}
	}
	for _, prefix := range excluded {
		if prefix.Contains(ip) {
			return Location{Status: "non_public"}
		}
	}
	if s == nil {
		return Location{Status: "unavailable"}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.reader == nil {
		return Location{Status: "unavailable"}
	}
	result := s.reader.Lookup(ip)
	if result.Err() != nil {
		return Location{Status: "lookup_error"}
	}
	if !result.Found() {
		return Location{Status: "not_found"}
	}
	var row record
	if result.Decode(&row) != nil {
		return Location{Status: "lookup_error"}
	}
	if row.Country.ISO == "" || row.Country.ISO == "ZZ" {
		return Location{Status: "not_found"}
	}
	if len(row.Country.ISO) != 2 || row.Country.ISO[0] < 'A' || row.Country.ISO[0] > 'Z' || row.Country.ISO[1] < 'A' || row.Country.ISO[1] > 'Z' {
		return Location{Status: "lookup_error"}
	}
	country, valid := locationName(row.Country.Names)
	city, validCity := locationName(row.City.Names)
	region := ""
	validRegion := true
	if len(row.Subdivisions) > 0 {
		region, validRegion = locationName(row.Subdivisions[0].Names)
	}
	if !valid || !validCity || !validRegion {
		return Location{Status: "lookup_error"}
	}
	lat, lon := row.Location.Latitude, row.Location.Longitude
	if (lat == nil) != (lon == nil) || lat != nil && (math.IsNaN(*lat) || math.IsInf(*lat, 0) || *lat < -90 || *lat > 90 || math.IsNaN(*lon) || math.IsInf(*lon, 0) || *lon < -180 || *lon > 180) {
		return Location{Status: "lookup_error"}
	}
	return Location{Status: "located", CountryCode: row.Country.ISO, Country: country, Region: region, City: city, Latitude: lat, Longitude: lon}
}
