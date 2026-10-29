package geodata

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const CountryChannel = "dbip-country-lite-v1"
const CountrySignatureDomain = "yunzhan-geodata-countries-v1\n"
const MaxCountryManifestBytes = 256 << 10
const MaxCountryPublishBytes int64 = 256 << 20

type CountryAsset struct {
	Code     string `json:"code"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	Networks int    `json:"networks"`
}

// Both nested documents are exact strings: their own closed parsers reject
// duplicate/case-aliased fields. Parent signature binds the original provider
// bytes; the DIFFERENT country domain binds this derived asset inventory.
type CountryManifest struct {
	Format          int    `json:"format"`
	Channel         string `json:"channel"`
	Release         string `json:"release"`
	Revision        int    `json:"revision"`
	BuildEpoch      uint64 `json:"build_epoch"`
	ParentManifest  string `json:"parent_manifest"`
	ParentSignature string `json:"parent_signature"`
	GeneratorSHA256 string `json:"generator_sha256"`
	AssetsJSON      string `json:"assets_json"`
	Bytes           int64  `json:"bytes"`
	Networks        int    `json:"networks"`
	License         string `json:"license"`
	AttributionURL  string `json:"attribution_url"`
}

type CountryAuthority struct {
	manifest       CountryManifest
	parent         Authority
	assets         []CountryAsset
	digest, keySHA string
	verified       bool
}

func (a CountryAuthority) SHA256() string            { return a.digest }
func (a CountryAuthority) KeySHA256() string         { return a.keySHA }
func (a CountryAuthority) Manifest() CountryManifest { return a.manifest }
func (a CountryAuthority) Assets() []CountryAsset    { return append([]CountryAsset(nil), a.assets...) }

// Expiry only gates a NEW activation. It is not permission to remove an
// already running policy or discard the original signed historical data.
func (a CountryAuthority) StaleForNewPolicy(now time.Time) bool {
	if !a.verified || now.IsZero() {
		return true
	}
	built := time.Unix(int64(a.manifest.BuildEpoch), 0)
	return now.Before(built) || now.Sub(built) > 90*24*time.Hour
}

func countryClosedObject(d *json.Decoder, fields []string) error {
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("country manifest object missing")
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return errors.New("country manifest duplicate, unknown or case-aliased field")
		}
		seen[name] = true
		value, err := d.Token()
		if _, nested := value.(json.Delim); err != nil || value == nil || nested {
			return errors.New("country manifest field is null, nested or incomplete")
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return errors.New("country manifest object incomplete")
	}
	return nil
}

func decodeCountryManifest(raw []byte) (CountryManifest, []CountryAsset, error) {
	var m CountryManifest
	if len(raw) == 0 || len(raw) > MaxCountryManifestBytes || !utf8.Valid(raw) {
		return m, nil, errors.New("country manifest bytes invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := countryClosedObject(d, []string{"format", "channel", "release", "revision", "build_epoch", "parent_manifest", "parent_signature", "generator_sha256", "assets_json", "bytes", "networks", "license", "attribution_url"}); err != nil {
		return m, nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return m, nil, errors.New("country manifest trailing document")
	}
	if json.Unmarshal(raw, &m) != nil || !utf8.ValidString(m.AssetsJSON) {
		return m, nil, errors.New("country manifest typed data invalid")
	}
	d = json.NewDecoder(strings.NewReader(m.AssetsJSON))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('[') {
		return m, nil, errors.New("country manifest assets array missing")
	}
	count := 0
	for d.More() {
		count++
		if count > 675 {
			return m, nil, errors.New("country manifest assets exceed code capacity")
		}
		if err := countryClosedObject(d, []string{"code", "bytes", "sha256", "networks"}); err != nil {
			return m, nil, err
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') || count == 0 {
		return m, nil, errors.New("country manifest assets incomplete or empty")
	}
	if _, err := d.Token(); err != io.EOF {
		return m, nil, errors.New("country manifest assets trailing data")
	}
	var assets []CountryAsset
	if json.Unmarshal([]byte(m.AssetsJSON), &assets) != nil || len(assets) != count {
		return m, nil, errors.New("country manifest typed assets invalid")
	}
	return m, assets, nil
}

func VerifyCountryManifest(raw, signature []byte, public ed25519.PublicKey, now time.Time, previous *CountryAuthority) (CountryAuthority, error) {
	var empty CountryAuthority
	if len(raw) == 0 || len(raw) > MaxCountryManifestBytes || len(signature) > 128 || len(public) != ed25519.PublicKeySize || now.Year() < 2026 {
		return empty, errors.New("country signature inputs or clock invalid")
	}
	raw = bytes.Clone(raw)
	text := strings.TrimSuffix(string(signature), "\n")
	sig, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != text || !ed25519.Verify(public, append([]byte(CountrySignatureDomain), raw...), sig) {
		return empty, errors.New("derived country manifest signature invalid")
	}
	m, assets, err := decodeCountryManifest(raw)
	if err != nil {
		return empty, err
	}
	if m.Format != 1 || m.Channel != CountryChannel || !releasePattern.MatchString(m.Release) || m.Revision < 1 || m.Revision > 1000 || !digestPattern.MatchString(m.GeneratorSHA256) || m.License != LicenseURL || m.AttributionURL != AttributionURL {
		return empty, errors.New("derived country format, generator, revision or attribution invalid")
	}
	var oldParent *Authority
	if previous != nil {
		if !previous.verified || previous.keySHA != hash(public) {
			return empty, errors.New("country previous authority missing or belongs to another key")
		}
		oldParent = &previous.parent
	}
	parent, err := VerifyManifest([]byte(m.ParentManifest), []byte(m.ParentSignature), public, now, oldParent)
	if err != nil || m.Release != parent.manifest.Release || m.BuildEpoch != parent.manifest.BuildEpoch {
		return empty, errors.New("country parent signature, release, epoch or rollback differs")
	}
	totalBytes, totalNetworks := int64(0), 0
	for i, a := range assets {
		if !countryCodeValid(a.Code) || i > 0 && assets[i-1].Code >= a.Code || a.Bytes < 1 || a.Bytes > MaxCountryCIDRBytes || !digestPattern.MatchString(a.SHA256) || a.Networks < 1 || a.Networks > maxCountryNetworks {
			return empty, errors.New("country asset code, count, order or byte/hash budget invalid")
		}
		totalBytes += a.Bytes
		totalNetworks += a.Networks
		if totalBytes > MaxCountryPublishBytes || totalNetworks > maxCountryPublishNetworks {
			return empty, errors.New("country publisher inventory exceeds fixed aggregate capacity")
		}
	}
	if m.Bytes != totalBytes || m.Networks != totalNetworks {
		return empty, errors.New("country complete inventory counts do not match actual descriptors")
	}
	digest := hash(raw)
	if previous != nil && (m.Release < previous.manifest.Release || m.Release == previous.manifest.Release && (m.Revision < previous.manifest.Revision || m.Revision == previous.manifest.Revision && digest != previous.digest)) {
		return empty, errors.New("country manifest rollback or same-revision replacement refused")
	}
	return CountryAuthority{manifest: m, parent: parent, assets: assets, digest: digest, keySHA: hash(public), verified: true}, nil
}

// Selection is the ORIGINAL per-activation one-million-network/64MiB budget,
// NOT the offline publisher's larger multi-country inventory. No partial list.
func (a CountryAuthority) Select(codes []string) ([]CountryAsset, error) {
	if !a.verified || len(codes) < 1 || len(codes) > 32 {
		return nil, errors.New("country selection authority or count missing")
	}
	assets := make([]CountryAsset, 0, len(codes))
	bytes, networks := int64(0), 0
	for i, code := range codes {
		if !countryCodeValid(code) || i > 0 && codes[i-1] >= code {
			return nil, errors.New("country selection must be canonical sorted unique codes")
		}
		at := sort.Search(len(a.assets), func(i int) bool { return a.assets[i].Code >= code })
		if at == len(a.assets) || a.assets[at].Code != code {
			return nil, errors.New("selected country has no signed public coverage")
		}
		asset := a.assets[at]
		bytes += asset.Bytes
		networks += asset.Networks
		if bytes > MaxCountryCIDRBytes || networks > maxCountryNetworks {
			return nil, errors.New("country activation exceeds original selected-data resource capacity")
		}
		assets = append(assets, asset)
	}
	return assets, nil
}

// Original-key derived authority + exact file bytes + independent canonical
// parsing + exact original-parent provenance are ALL mandatory. A format-only
// publisher receipt is not accepted here as signature or install authority.
func VerifyCountryAsset(ctx context.Context, a CountryAuthority, code string, input io.Reader) (CountryCIDRMetadata, error) {
	var empty CountryCIDRMetadata
	if ctx == nil || input == nil || !a.verified {
		return empty, errors.New("country asset context, stream or derived authority missing")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	selected, err := a.Select([]string{code})
	if err != nil {
		return empty, err
	}
	asset := selected[0]
	limited := &io.LimitedReader{R: input, N: asset.Bytes + 1}
	metadata, err := ValidateCountryCIDR(ctx, limited)
	if err != nil {
		return empty, err
	}
	if err := verifyCountryAssetMetadata(a, asset, metadata); err != nil {
		return empty, err
	}
	return metadata, nil
}

func verifyCountryAssetMetadata(a CountryAuthority, asset CountryAsset, metadata CountryCIDRMetadata) error {
	if !a.verified || metadata.Bytes != asset.Bytes || metadata.SHA256 != asset.SHA256 || metadata.Networks != asset.Networks || len(metadata.Countries) != 1 || metadata.Countries[0].Code != asset.Code || metadata.Countries[0].Networks != asset.Networks || metadata.ParentManifestSHA256 != a.parent.digest || metadata.ParentDatabaseSHA256 != a.parent.manifest.SHA256 {
		return errors.New("country asset bytes, coverage, labels or parent identity differ from signed inventory")
	}
	return nil
}
