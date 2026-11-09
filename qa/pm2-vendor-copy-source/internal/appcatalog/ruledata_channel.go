package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/rulefeed"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const ruleDataChannelID = "et-open-web-bsd-v1"
const ruleDataDomain = "yunzhan-rulefeed-channel-v1\n"
const maxRuleDataCatalogBytes = 32 << 10

// An immutable app release declares only this closed data ABI. Daily data is
// independently signed and never changes the app release's version or digest.
// Paths, executable commands, keys and installer privileges are not declarations.
type RuleDataChannel struct {
	ID     string `json:"id"`
	Format int    `json:"format"`
	Engine string `json:"engine"`
}

type RuleDataCatalog struct {
	SchemaVersion int      `json:"schema_version"`
	Channel       string   `json:"channel"`
	Sequence      uint64   `json:"sequence"`
	PublishedAt   string   `json:"published_at"`
	ExpiresAt     string   `json:"expires_at"`
	Feed          RuleFeed `json:"feed"`
}

// Authority is deliberately opaque: it cannot be decoded from a request or
// constructed from a boolean. Every receiver verifies the original signatures.
type RuleDataAuthority struct {
	manifest                                                          Manifest
	catalog                                                           RuleDataCatalog
	baseURL, keySHA, appSHA, catalogSHA                               string
	appCatalog, appSignature, appManifest, dataCatalog, dataSignature []byte
	verified                                                          bool
}

type RuleDataEnvelope struct {
	AppCatalog    []byte            `json:"app_catalog"`
	AppSignature  []byte            `json:"app_signature"`
	AppManifest   []byte            `json:"app_manifest"`
	DataCatalog   []byte            `json:"data_catalog"`
	DataSignature []byte            `json:"data_signature"`
	Files         map[string][]byte `json:"files"`
}

func detachedRuleDataCatalog(value RuleDataCatalog) RuleDataCatalog {
	value.Feed.Assets = append([]RuleFeedAsset(nil), value.Feed.Assets...)
	return value
}

func (value RuleDataAuthority) Catalog() RuleDataCatalog {
	return detachedRuleDataCatalog(value.catalog)
}
func (value RuleDataAuthority) CatalogSHA256() string { return value.catalogSHA }

// closedRuleDataJSON rejects duplicate keys at every depth, aliases, nulls,
// invalid UTF-8 and trailing values before decoding exact case-sensitive fields.
func closedRuleDataJSON(raw []byte, out any) error {
	if !utf8.Valid(raw) {
		return errors.New("规则数据 JSON 编码无效")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	allowed := map[string]bool{"schema_version": true, "channel": true, "sequence": true, "published_at": true, "expires_at": true, "feed": true, "id": true, "manifest_sha256": true, "assets": true, "name": true, "sha256": true, "bytes": true, "catalog": true, "signature": true}
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 6 {
			return errors.New("规则数据 JSON 嵌套超限")
		}
		token, err := decoder.Token()
		if err != nil || token == nil {
			return errors.New("规则数据 JSON 不完整或含 null")
		}
		delim, nested := token.(json.Delim)
		if !nested {
			if depth == 0 {
				return errors.New("规则数据 JSON 须为对象")
			}
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || !allowed[name] || seen[name] {
					return errors.New("规则数据 JSON 包含重复、未知或非规范字段")
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			if depth == 0 {
				return errors.New("规则数据 JSON 须为对象")
			}
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("规则数据 JSON 结构无效")
		}
		end, err := decoder.Token()
		if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return errors.New("规则数据 JSON 未闭合")
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("规则数据 JSON 包含多余值")
	}
	return strictJSON(raw, out)
}

func canonicalRuleDataTime(text string) (time.Time, error) {
	value, err := time.Parse(time.RFC3339, text)
	if err != nil || value.UTC().Format(time.RFC3339) != text {
		return time.Time{}, errors.New("规则数据时间须为规范 UTC 秒")
	}
	return value, nil
}

func (client *Client) VerifyRuleDataAuthority(appCatalog, appSignature, appManifest, dataCatalog, dataSignature []byte, version, appSHA string, now time.Time, previous *RuleDataAuthority) (RuleDataAuthority, error) {
	var empty RuleDataAuthority
	if client == nil || len(client.PublicKey) != ed25519.PublicKeySize || len(appCatalog) == 0 || len(appCatalog) > maxCatalogBytes || len(appSignature) == 0 || len(appSignature) > 4096 || len(appManifest) == 0 || len(appManifest) > maxManifestBytes || len(dataCatalog) == 0 || len(dataCatalog) > maxRuleDataCatalogBytes || len(dataSignature) == 0 || len(dataSignature) > 4096 || !ValidVersion(version) || !ruleFeedSHAPattern.MatchString(appSHA) || now.Year() < 2026 {
		return empty, errors.New("规则数据双签名输入、应用绑定或时钟无效")
	}
	// Copy before verification, so retained authority never aliases request data.
	appCatalog = bytes.Clone(appCatalog)
	appSignature = bytes.Clone(appSignature)
	appManifest = bytes.Clone(appManifest)
	dataCatalog = bytes.Clone(dataCatalog)
	dataSignature = bytes.Clone(dataSignature)
	apps, err := client.verifyCatalog(appCatalog, appSignature)
	if err != nil {
		return empty, err
	}
	item, ok := Find(apps, "network-threat-detection")
	if !ok || item.Version != version || item.SHA256 != appSHA {
		return empty, errors.New("规则数据不属于指定已签名应用")
	}
	manifest, err := client.verifyManifestData(item, appManifest)
	if err != nil {
		return empty, err
	}
	if manifest.RuleDataChannel == nil || validateRuleFeeds(manifest) != nil {
		return empty, errors.New("已签名应用没有授权固定规则数据通道")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(dataSignature)))
	message := append([]byte(ruleDataDomain), dataCatalog...)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(client.PublicKey, message, signature) {
		return empty, errors.New("规则数据通道的独立 Ed25519 签名无效")
	}
	var catalog RuleDataCatalog
	if err := closedRuleDataJSON(dataCatalog, &catalog); err != nil {
		return empty, err
	}
	if catalog.SchemaVersion != 1 || catalog.Channel != ruleDataChannelID || catalog.Sequence == 0 {
		return empty, errors.New("规则数据通道版本、身份或序号无效")
	}
	// Reuse the same closed six-file and per-file budget contract as inline data.
	inline := manifest
	inline.RuleDataChannel = nil
	inline.RuleFeeds = []RuleFeed{catalog.Feed}
	if err := validateRuleFeeds(inline); err != nil {
		return empty, err
	}
	published, err := canonicalRuleDataTime(catalog.PublishedAt)
	if err != nil {
		return empty, err
	}
	expires, err := canonicalRuleDataTime(catalog.ExpiresAt)
	if err != nil || !expires.After(published) || expires.Sub(published) > 72*time.Hour || now.Before(published.Add(-5*time.Minute)) || !now.Before(expires) {
		return empty, errors.New("规则数据目录未来、过期或超过 72 小时有效期")
	}
	date, err := time.Parse("20060102", strings.TrimPrefix(catalog.Feed.ID, "et-open-web-"))
	if err != nil || published.Before(date) || published.Sub(date) >= 72*time.Hour {
		return empty, errors.New("规则数据发布日期与规则版本不同或过旧")
	}
	keySHA := hashRuleFeedFile(client.PublicKey)
	catalogSHA := hashRuleFeedFile(dataCatalog)
	if previous != nil {
		if !previous.verified || previous.baseURL != client.BaseURL || previous.keySHA != keySHA || previous.catalog.Channel != catalog.Channel {
			return empty, errors.New("规则数据进度不属于本仓库的独立验签记录")
		}
		if catalog.Sequence < previous.catalog.Sequence || catalog.Sequence == previous.catalog.Sequence && catalogSHA != previous.catalogSHA || catalog.PublishedAt < previous.catalog.PublishedAt || catalog.Feed.ID < previous.catalog.Feed.ID {
			return empty, errors.New("拒绝规则数据序号、日期回退或同序号改写")
		}
	}
	return RuleDataAuthority{manifest: manifest, catalog: detachedRuleDataCatalog(catalog), baseURL: client.BaseURL, keySHA: keySHA, appSHA: appSHA, catalogSHA: catalogSHA, appCatalog: appCatalog, appSignature: appSignature, appManifest: appManifest, dataCatalog: dataCatalog, dataSignature: dataSignature, verified: true}, nil
}

// Retained signed history is only an anti-rollback cursor. It may be expired;
// downloading or installing still independently checks current time. A caller
// cannot turn this cursor into fresh authority by claiming an earlier clock.
func (client *Client) VerifyRetainedRuleDataAuthority(appCatalog, appSignature, appManifest, dataCatalog, dataSignature []byte, version, appSHA string, now time.Time) (RuleDataAuthority, error) {
	var empty RuleDataAuthority
	if len(dataCatalog) == 0 || len(dataCatalog) > maxRuleDataCatalogBytes || now.Year() < 2026 {
		return empty, errors.New("规则数据历史容量或本机时钟无效")
	}
	var catalog RuleDataCatalog
	if err := closedRuleDataJSON(dataCatalog, &catalog); err != nil {
		return empty, err
	}
	published, err := canonicalRuleDataTime(catalog.PublishedAt)
	if err != nil || now.Before(published.Add(-5*time.Minute)) {
		return empty, errors.New("规则数据历史不能来自未来")
	}
	return client.VerifyRuleDataAuthority(appCatalog, appSignature, appManifest, dataCatalog, dataSignature, version, appSHA, published, nil)
}

func (client *Client) fetchRuleDataAuthorityForApp(ctx context.Context, raw, sig, manifestRaw []byte, version, appSHA string, now time.Time, previous *RuleDataAuthority) (RuleDataAuthority, error) {
	var empty RuleDataAuthority
	path := client.BaseURL + "/dist/apps/network-threat-detection/rule-data/" + ruleDataChannelID + "/catalog-v1.bundle.json"
	bundleRaw, err := client.get(ctx, path, 2*maxRuleDataCatalogBytes)
	if err != nil {
		return empty, err
	}
	var bundle catalogBundle
	if err := closedRuleDataJSON(bundleRaw, &bundle); err != nil {
		return empty, err
	}
	return client.VerifyRuleDataAuthority(raw, sig, manifestRaw, []byte(bundle.Catalog), []byte(bundle.Signature), version, appSHA, now, previous)
}

func guardedRuleDataClient(client *Client) (*Client, error) {
	if client == nil || client.HTTP == nil || len(client.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("规则数据仓库未初始化")
	}
	transport := *client.HTTP
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{BaseURL: client.BaseURL, PublicKey: bytes.Clone(client.PublicKey), HTTP: &transport}, nil
}

// Metadata-only check: signed app bundle, app manifest, and one atomic data
// bundle. Missing, malformed or unreachable data never falls back to inline data.
func (client *Client) FetchRuleDataAuthority(ctx context.Context, version, appSHA string, now time.Time, previous *RuleDataAuthority) (RuleDataAuthority, error) {
	var empty RuleDataAuthority
	guarded, err := guardedRuleDataClient(client)
	if err != nil {
		return empty, err
	}
	apps, raw, sig, err := guarded.FetchCatalog(ctx)
	if err != nil {
		return empty, err
	}
	item, ok := Find(apps, "network-threat-detection")
	if !ok || item.Version != version || item.SHA256 != appSHA {
		return empty, errors.New("规则数据应用目录已变化")
	}
	manifestRaw, err := guarded.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, err
	}
	manifest, err := guarded.verifyManifestData(item, manifestRaw)
	if err != nil {
		return empty, err
	}
	if manifest.RuleDataChannel == nil {
		return empty, errors.New("应用未声明规则数据通道")
	}
	return guarded.fetchRuleDataAuthorityForApp(ctx, raw, sig, manifestRaw, version, appSHA, now, previous)
}

func (client *Client) FetchRuleDataEnvelope(ctx context.Context, authority RuleDataAuthority, now time.Time) (RuleDataEnvelope, error) {
	var empty RuleDataEnvelope
	guarded, err := guardedRuleDataClient(client)
	if err != nil {
		return empty, err
	}
	if !authority.verified || authority.baseURL != client.BaseURL || authority.keySHA != hashRuleFeedFile(client.PublicKey) {
		return empty, errors.New("规则数据没有本仓库的独立授权")
	}
	// Recheck expiry immediately before downloading, not only when the UI checked.
	authority, err = guarded.VerifyRuleDataAuthority(authority.appCatalog, authority.appSignature, authority.appManifest, authority.dataCatalog, authority.dataSignature, authority.manifest.Version, authority.appSHA, now, &authority)
	if err != nil {
		return empty, err
	}
	files := map[string][]byte{}
	for _, asset := range authority.catalog.Feed.Assets {
		path := guarded.BaseURL + "/dist/apps/network-threat-detection/rule-data/" + ruleDataChannelID + "/feeds/" + authority.catalog.Feed.ID + "/" + authority.catalog.Feed.ManifestSHA256 + "/" + asset.Name
		data, err := guarded.get(ctx, path, int64(asset.Bytes))
		if err != nil {
			return empty, err
		}
		files[asset.Name] = data
	}
	if _, err := verifyRuleFeedFiles(ctx, authority.catalog.Feed, files); err != nil {
		return empty, err
	}
	return RuleDataEnvelope{AppCatalog: bytes.Clone(authority.appCatalog), AppSignature: bytes.Clone(authority.appSignature), AppManifest: bytes.Clone(authority.appManifest), DataCatalog: bytes.Clone(authority.dataCatalog), DataSignature: bytes.Clone(authority.dataSignature), Files: files}, nil
}

// Root receivers use their own pinned Client, their own clock and any retained
// independently verified progress. No API-supplied authority or HTTP is trusted.
func (client *Client) VerifyRuleDataEnvelope(ctx context.Context, in RuleDataEnvelope, version, appSHA, feedID, ruleSHA string, now time.Time, previous *RuleDataAuthority) (RuleDataAuthority, *rulefeed.Bundle, error) {
	var empty RuleDataAuthority
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	if !ruleFeedIDPattern.MatchString(feedID) || !ruleFeedSHAPattern.MatchString(ruleSHA) || len(in.Files) != len(ruleFeedFileLimits) {
		return empty, nil, errors.New("规则数据任务选择或文件集合无效")
	}
	files := map[string][]byte{}
	for name, limit := range ruleFeedFileLimits {
		data, ok := in.Files[name]
		if !ok || len(data) < 1 || len(data) > limit {
			return empty, nil, errors.New("规则数据文件缺失或超限")
		}
		files[name] = bytes.Clone(data)
	}
	authority, err := client.VerifyRuleDataAuthority(in.AppCatalog, in.AppSignature, in.AppManifest, in.DataCatalog, in.DataSignature, version, appSHA, now, previous)
	if err != nil {
		return empty, nil, err
	}
	if authority.catalog.Feed.ID != feedID || authority.catalog.Feed.ManifestSHA256 != ruleSHA {
		return empty, nil, errors.New("规则数据与任务选择不同")
	}
	bundle, err := verifyRuleFeedFiles(ctx, authority.catalog.Feed, files)
	return authority, bundle, err
}
