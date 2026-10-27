package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"local/panel/internal/geodata"
)

const MaxGeoDataEnvelopeBytes = 3 << 20

// The immutable app authorizes a closed data-only ABI, never a URL, executable,
// signing key or writable path. Data releases have their own domain signature.
type GeoDataChannel struct {
	ID     string `json:"id"`
	Format int    `json:"format"`
}

func validateGeoDataChannel(m Manifest) error {
	hasFeature := false
	for _, feature := range m.RequiredPanelFeatures {
		hasFeature = hasFeature || feature == StatisticsGeographyFeature
	}
	if hasFeature && (m.ID != "website-statistics-v2" || m.Version != "2.6.0" || m.GeoDataChannel == nil) {
		return errors.New("地域处理器声明不能用于旧版、别名或无授权通道的应用")
	}
	if m.GeoDataChannel == nil {
		base, _, _ := strings.Cut(m.Version, "-")
		if m.ID == "website-statistics-v2" {
			if cmp, ok := CompareVersions(base, "2.6.0"); ok && cmp >= 0 {
				return errors.New("统计地域版本缺少固定数据通道")
			}
		}
		return nil
	}
	if !hasFeature || m.ID != "website-statistics-v2" || m.Version != "2.6.0" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.GeoDataChannel.ID != geodata.Channel || m.GeoDataChannel.Format != 1 {
		return errors.New("地理数据通道不属于已实现的固定统计应用")
	}
	return nil
}

type GeoDataEnvelope struct {
	AppCatalog    []byte `json:"app_catalog"`
	AppSignature  []byte `json:"app_signature"`
	AppManifest   []byte `json:"app_manifest"`
	DataManifest  []byte `json:"data_manifest"`
	DataSignature []byte `json:"data_signature"`
}
type GeoDataAuthority struct {
	data                       geodata.Authority
	appVersion, appSHA, keySHA string
	envelope                   GeoDataEnvelope
	verified                   bool
}

func (a GeoDataAuthority) Data() geodata.Authority   { return a.data }
func (a GeoDataAuthority) AppVersion() string        { return a.appVersion }
func (a GeoDataAuthority) AppSHA256() string         { return a.appSHA }
func (a GeoDataAuthority) Envelope() GeoDataEnvelope { return cloneGeoEnvelope(a.envelope) }
func cloneGeoEnvelope(in GeoDataEnvelope) GeoDataEnvelope {
	return GeoDataEnvelope{bytes.Clone(in.AppCatalog), bytes.Clone(in.AppSignature), bytes.Clone(in.AppManifest), bytes.Clone(in.DataManifest), bytes.Clone(in.DataSignature)}
}

func DecodeGeoDataEnvelope(raw []byte) (GeoDataEnvelope, error) {
	var empty GeoDataEnvelope
	if len(raw) < 1 || len(raw) > MaxGeoDataEnvelopeBytes || !utf8.Valid(raw) {
		return empty, errors.New("地理数据交付容量或编码无效")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return empty, errors.New("地理数据交付须为闭合对象")
	}
	allowed := map[string]bool{"app_catalog": true, "app_signature": true, "app_manifest": true, "data_manifest": true, "data_signature": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return empty, errors.New("地理数据交付字段重复、未知或名称不规范")
		}
		seen[name] = true
		value, err := d.Token()
		if _, ok := value.(string); err != nil || !ok {
			return empty, errors.New("地理数据交付只接受原始签名材料")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return empty, errors.New("地理数据交付字段不完整")
	}
	if _, err := d.Token(); err != io.EOF {
		return empty, errors.New("地理数据交付含多余值")
	}
	var out GeoDataEnvelope
	if err := json.Unmarshal(raw, &out); err != nil {
		return empty, errors.New("地理数据签名材料编码无效")
	}
	return out, nil
}

func (c *Client) VerifyGeoDataEnvelope(in GeoDataEnvelope, version, appSHA string, now time.Time, previous *GeoDataAuthority) (GeoDataAuthority, error) {
	var empty GeoDataAuthority
	if c == nil || len(c.PublicKey) != ed25519.PublicKeySize || version != "2.6.0" || !digestPatternForGeo(appSHA) || len(in.AppCatalog) < 1 || len(in.AppCatalog) > maxCatalogBytes || len(in.AppSignature) < 1 || len(in.AppSignature) > 4096 || len(in.AppManifest) < 1 || len(in.AppManifest) > maxManifestBytes || len(in.DataManifest) < 1 || len(in.DataManifest) > 4096 || len(in.DataSignature) < 1 || len(in.DataSignature) > 128 {
		return empty, errors.New("地理数据应用绑定或独立验签输入无效")
	}
	in = cloneGeoEnvelope(in)
	catalog, err := c.verifyCatalog(in.AppCatalog, in.AppSignature)
	if err != nil {
		return empty, err
	}
	item, found := Find(catalog, "website-statistics-v2")
	if !found || item.Version != version || item.SHA256 != appSHA {
		return empty, errors.New("地理数据不属于所选已签名统计应用")
	}
	manifest, err := c.verifyManifestData(item, in.AppManifest)
	if err != nil || manifest.GeoDataChannel == nil || validateGeoDataChannel(manifest) != nil {
		return empty, errors.New("地理数据的应用授权通道无法核对")
	}
	keySHA := hashRuleFeedFile(c.PublicKey)
	var prior *geodata.Authority
	if previous != nil {
		if !previous.verified || previous.keySHA != keySHA || previous.appVersion != version || previous.appSHA != appSHA {
			return empty, errors.New("旧地理数据不属于相同的受信应用绑定")
		}
		prior = &previous.data
	}
	data, err := geodata.VerifyManifest(in.DataManifest, in.DataSignature, c.PublicKey, now, prior)
	if err != nil {
		return empty, err
	}
	return GeoDataAuthority{data: data, appVersion: version, appSHA: appSHA, keySHA: keySHA, envelope: in, verified: true}, nil
}
func digestPatternForGeo(text string) bool {
	if len(text) != 64 {
		return false
	}
	for _, ch := range text {
		if ch < '0' || ch > '9' && ch < 'a' || ch > 'f' {
			return false
		}
	}
	return true
}

// Stream directly to a private staging file. Neither an arbitrary caller URL
// nor authentication/cookies are sent to the fixed provider. A partial writer
// or failed response is not accepted as an installed dataset.
func (c *Client) DownloadGeoDatabase(ctx context.Context, a GeoDataAuthority, destination io.Writer) error {
	if ctx == nil || c == nil || c.HTTP == nil || destination == nil || !a.verified || a.keySHA != hashRuleFeedFile(c.PublicKey) {
		return errors.New("地理数据下载缺少独立授权")
	}
	m := a.data.Manifest()
	request, err := http.NewRequestWithContext(ctx, "GET", m.Source, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept-Encoding", "identity")
	client := *c.HTTP
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Catalog requests use12s. A60MiB monthly dataset needs its own bounded
	// download budget; the worker/caller context may still impose a shorter one.
	client.Timeout = 240 * time.Second
	response, err := client.Do(request)
	if err != nil {
		return errors.New("地理数据 HTTPS 下载失败，未选择新库")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Uncompressed || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" || response.ContentLength >= 0 && response.ContentLength != m.CompressedBytes {
		return errors.New("地理数据响应状态、编码或大小不符")
	}
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(destination, digest), io.LimitReader(response.Body, m.CompressedBytes+1))
	if err != nil || n != m.CompressedBytes || hex.EncodeToString(digest.Sum(nil)) != m.CompressedSHA256 {
		return errors.New("地理数据下载未完整校验；保留原库")
	}
	return ctx.Err()
}

// Fetch only small, independently signed authority material. Root downloads
// the database itself. A newer preview cannot replace an old job's selection.
func (c *Client) FetchGeoDataEnvelope(ctx context.Context, expectedDataSHA string, now time.Time) (GeoDataEnvelope, GeoDataAuthority, error) {
	var empty GeoDataEnvelope
	var none GeoDataAuthority
	if c == nil || c.HTTP == nil || expectedDataSHA != "" && !digestPatternForGeo(expectedDataSHA) {
		return empty, none, errors.New("地域仓库选择无效")
	}
	httpClient := *c.HTTP
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	guarded := &Client{BaseURL: c.BaseURL, PublicKey: bytes.Clone(c.PublicKey), HTTP: &httpClient}
	catalog, raw, sig, err := guarded.FetchCatalog(ctx)
	if err != nil {
		return empty, none, err
	}
	item, found := Find(catalog, "website-statistics-v2")
	if !found || item.Version != "2.6.0" {
		return empty, none, errors.New("签名仓库尚未提供统计2.6地域数据通道")
	}
	manifest, err := guarded.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, none, err
	}
	bundle, err := guarded.get(ctx, guarded.BaseURL+"/data/geodata/"+geodata.Channel+"/catalog.signed.json", 8192)
	if err != nil {
		return empty, none, err
	}
	var value struct {
		Manifest  string `json:"manifest"`
		Signature string `json:"signature"`
	}
	if len(bundle) == 0 || !utf8.Valid(bundle) {
		return empty, none, errors.New("地域数据目录编码或容量无效")
	}
	d := json.NewDecoder(bytes.NewReader(bundle))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return empty, none, errors.New("地域数据目录须为闭合对象")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || name != "manifest" && name != "signature" || seen[name] {
			return empty, none, errors.New("地域数据目录字段重复或未知")
		}
		seen[name] = true
		v, err := d.Token()
		if _, ok := v.(string); err != nil || !ok {
			return empty, none, errors.New("地域数据目录只接受原始签名文本")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != 2 {
		return empty, none, errors.New("地域数据目录不完整")
	}
	if _, err = d.Token(); err != io.EOF {
		return empty, none, errors.New("地域数据目录含多余值")
	}
	if json.Unmarshal(bundle, &value) != nil {
		return empty, none, errors.New("地域数据目录解码失败")
	}
	in := GeoDataEnvelope{AppCatalog: raw, AppSignature: sig, AppManifest: manifest, DataManifest: []byte(value.Manifest), DataSignature: []byte(value.Signature)}
	a, err := guarded.VerifyGeoDataEnvelope(in, item.Version, item.SHA256, now, nil)
	if err != nil {
		return empty, none, err
	}
	if expectedDataSHA != "" && a.Data().SHA256() != expectedDataSHA {
		return empty, none, errors.New("地域数据签名目录已变化，请刷新后重新选择")
	}
	return a.Envelope(), a, nil
}
