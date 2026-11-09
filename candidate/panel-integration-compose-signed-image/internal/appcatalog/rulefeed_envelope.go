package appcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/rulefeed"
	"net/http"
	"strings"
	"time"
)

// The receiver has its own pinned Client. The envelope deliberately contains
// no public key, repository URL, verification flag, executable or destination.
// JSON encodes byte slices as base64 to preserve exact signed bytes.
const MaxRuleFeedEnvelopeBytes = 16 << 20

type RuleFeedEnvelope struct {
	Catalog       []byte            `json:"catalog"`
	Signature     []byte            `json:"signature"`
	AppManifest   []byte            `json:"app_manifest"`
	FeedID        string            `json:"feed_id"`
	Files         map[string][]byte `json:"files"`
	DataCatalog   []byte            `json:"rule_data_catalog,omitempty"`
	DataSignature []byte            `json:"rule_data_signature,omitempty"`
}

// FetchRuleFeedEnvelope is an explicit data download, not installation or
// activation. A changed catalog cannot silently replace the requested binding.
func (client *Client) FetchRuleFeedEnvelope(ctx context.Context, version, manifestSHA, feedID string) (RuleFeedEnvelope, error) {
	return client.FetchRuleFeedEnvelopeAt(ctx, version, manifestSHA, feedID, time.Now())
}

func (client *Client) FetchRuleFeedEnvelopeAt(ctx context.Context, version, manifestSHA, feedID string, now time.Time) (RuleFeedEnvelope, error) {
	var empty RuleFeedEnvelope
	if client == nil || client.HTTP == nil || !versionPattern.MatchString(version) || !ruleFeedSHAPattern.MatchString(manifestSHA) || !ruleFeedIDPattern.MatchString(feedID) {
		return empty, errors.New("规则数据下载绑定无效")
	}
	transport := *client.HTTP
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	guarded := &Client{BaseURL: client.BaseURL, PublicKey: append([]byte(nil), client.PublicKey...), HTTP: &transport}
	catalog, raw, signature, err := guarded.FetchCatalog(ctx)
	if err != nil {
		return empty, err
	}
	item, ok := Find(catalog, "network-threat-detection")
	if !ok || item.Version != version || item.SHA256 != manifestSHA {
		return empty, errors.New("规则数据目录已变化，请刷新后重试")
	}
	manifest, err := guarded.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, err
	}
	decoded, err := guarded.verifyManifestData(item, manifest)
	if err != nil {
		return empty, err
	}
	if decoded.RuleDataChannel != nil {
		authority, err := guarded.fetchRuleDataAuthorityForApp(ctx, raw, signature, manifest, version, manifestSHA, now, nil)
		if err != nil {
			return empty, err
		}
		if authority.catalog.Feed.ID != feedID {
			return empty, errors.New("规则数据目录已变化，请刷新后重试")
		}
		in, err := guarded.FetchRuleDataEnvelope(ctx, authority, now)
		if err != nil {
			return empty, err
		}
		return RuleFeedEnvelope{Catalog: in.AppCatalog, Signature: in.AppSignature, AppManifest: in.AppManifest, FeedID: feedID, Files: in.Files, DataCatalog: in.DataCatalog, DataSignature: in.DataSignature}, nil
	}
	authority, err := guarded.VerifyRuleFeedAuthority(raw, signature, manifest, version, manifestSHA, feedID)
	if err != nil {
		return empty, err
	}
	bundle, err := guarded.FetchVerifiedRuleFeed(ctx, authority)
	if err != nil {
		return empty, err
	}
	return RuleFeedEnvelope{Catalog: raw, Signature: signature, AppManifest: manifest, FeedID: feedID, Files: bundle.Files}, nil
}

// VerifyRuleFeedEnvelope runs entirely offline and independently reconstructs
// signing authority. expectedVersion and expectedManifestSHA bind the job's
// requested app release, not an API assertion of trust. No network or writes.
func (client *Client) VerifyRuleFeedEnvelope(ctx context.Context, in RuleFeedEnvelope, expectedVersion, expectedManifestSHA string) (RuleFeedAuthority, *rulefeed.Bundle, error) {
	return client.VerifyRuleFeedEnvelopeAt(ctx, in, expectedVersion, expectedManifestSHA, time.Now())
}

func (client *Client) VerifyRuleFeedEnvelopeAt(ctx context.Context, in RuleFeedEnvelope, expectedVersion, expectedManifestSHA string, now time.Time) (RuleFeedAuthority, *rulefeed.Bundle, error) {
	var empty RuleFeedAuthority
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	if len(in.DataCatalog) > 0 || len(in.DataSignature) > 0 {
		var data RuleDataCatalog
		if len(in.DataCatalog) == 0 || len(in.DataSignature) == 0 || len(in.DataCatalog) > maxRuleDataCatalogBytes || closedRuleDataJSON(in.DataCatalog, &data) != nil {
			return empty, nil, errors.New("规则数据通道签名交付不完整")
		}
		authority, bundle, err := client.VerifyRuleDataEnvelope(ctx, RuleDataEnvelope{AppCatalog: in.Catalog, AppSignature: in.Signature, AppManifest: in.AppManifest, DataCatalog: in.DataCatalog, DataSignature: in.DataSignature, Files: in.Files}, expectedVersion, expectedManifestSHA, in.FeedID, data.Feed.ManifestSHA256, now, nil)
		if err != nil {
			return empty, nil, err
		}
		return RuleFeedAuthority{manifest: authority.manifest, feedID: in.FeedID, baseURL: authority.baseURL, keySHA: authority.keySHA, verified: true}, bundle, nil
	}
	if len(in.Files) != len(ruleFeedFileLimits) {
		return empty, nil, errors.New("规则数据交付集合无效")
	}
	files := map[string][]byte{}
	for name, limit := range ruleFeedFileLimits {
		data, ok := in.Files[name]
		if !ok || len(data) < 1 || len(data) > limit {
			return empty, nil, errors.New("规则数据交付成员缺失或超限")
		}
		files[name] = append([]byte(nil), data...)
	}
	authority, err := client.VerifyRuleFeedAuthority(in.Catalog, in.Signature, in.AppManifest, expectedVersion, expectedManifestSHA, in.FeedID)
	if err != nil {
		return empty, nil, err
	}
	for _, feed := range authority.manifest.RuleFeeds {
		if feed.ID == authority.feedID {
			bundle, err := verifyRuleFeedFiles(ctx, feed, files)
			return authority, bundle, err
		}
	}
	return empty, nil, errors.New("规则数据签名授权不完整")
}

// DecodeRuleFeedEnvelope rejects ambiguous keys, aliases, nulls, extensions,
// over-budget base64 input and trailing objects before any privileged writes.
func DecodeRuleFeedEnvelope(data []byte) (RuleFeedEnvelope, error) {
	var empty RuleFeedEnvelope
	if len(data) < 1 || len(data) > MaxRuleFeedEnvelopeBytes {
		return empty, errors.New("规则数据交付文本超过容量")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 3 {
			return errors.New("规则数据交付结构过深")
		}
		token, err := decoder.Token()
		if err != nil || token == nil {
			return errors.New("规则数据交付不完整或含 null")
		}
		if delim, ok := token.(json.Delim); ok {
			if delim != '{' {
				return errors.New("规则数据交付仅接受闭合对象")
			}
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[strings.ToLower(name)] {
					return errors.New("规则数据交付包含重复或歧义字段")
				}
				seen[strings.ToLower(name)] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("规则数据交付结构不完整")
			}
		} else if depth == 0 {
			return errors.New("规则数据交付必须是对象")
		}
		return nil
	}
	if err := value(0); err != nil {
		return empty, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return empty, errors.New("规则数据交付包含多余内容")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return empty, err
	}
	if len(fields) != 5 && len(fields) != 7 {
		return empty, errors.New("规则数据交付字段集合不完整")
	}
	for _, name := range []string{"catalog", "signature", "app_manifest", "feed_id", "files"} {
		if _, ok := fields[name]; !ok {
			return empty, errors.New("规则数据交付字段名称不规范")
		}
	}
	if len(fields) == 7 {
		for _, name := range []string{"rule_data_catalog", "rule_data_signature"} {
			if _, ok := fields[name]; !ok {
				return empty, errors.New("规则数据通道交付字段不完整")
			}
		}
	}
	if err := strictJSON(data, &empty); err != nil {
		return RuleFeedEnvelope{}, err
	}
	if len(empty.Catalog) < 1 || len(empty.Catalog) > maxCatalogBytes || len(empty.Signature) < 1 || len(empty.Signature) > 4096 || len(empty.AppManifest) < 1 || len(empty.AppManifest) > maxManifestBytes || !ruleFeedIDPattern.MatchString(empty.FeedID) || len(empty.Files) != len(ruleFeedFileLimits) {
		return RuleFeedEnvelope{}, errors.New("规则数据交付身份或容量无效")
	}
	if len(fields) == 7 && (len(empty.DataCatalog) == 0 || len(empty.DataCatalog) > maxRuleDataCatalogBytes || len(empty.DataSignature) == 0 || len(empty.DataSignature) > 4096) {
		return RuleFeedEnvelope{}, errors.New("规则数据通道交付为空或超限")
	}
	for name, limit := range ruleFeedFileLimits {
		if data, ok := empty.Files[name]; !ok || len(data) < 1 || len(data) > limit {
			return RuleFeedEnvelope{}, errors.New("规则数据交付文件集合无效")
		}
	}
	return empty, nil
}
