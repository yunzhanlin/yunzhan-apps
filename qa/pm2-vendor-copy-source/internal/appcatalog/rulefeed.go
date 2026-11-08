package appcatalog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"local/panel/internal/rulefeed"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type RuleFeedAsset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func hashRuleFeedFile(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

type RuleFeed struct {
	ID             string          `json:"id"`
	ManifestSHA256 string          `json:"manifest_sha256"`
	Assets         []RuleFeedAsset `json:"assets"`
}

// RuleFeedAuthority cannot be deserialized or assembled by API callers. The
// privileged receiver reconstructs it by independently verifying signed raw
// bytes, not by trusting the panel process's claim that a manifest was checked.
type RuleFeedAuthority struct {
	manifest                Manifest
	feedID, baseURL, keySHA string
	verified                bool
}

func (client *Client) VerifyRuleFeedAuthority(catalogRaw, signature, manifestRaw []byte, version, manifestSHA, feedID string) (RuleFeedAuthority, error) {
	var empty RuleFeedAuthority
	if client == nil || len(client.PublicKey) != 32 || len(catalogRaw) == 0 || len(catalogRaw) > maxCatalogBytes || len(signature) == 0 || len(signature) > 4096 || len(manifestRaw) == 0 || len(manifestRaw) > maxManifestBytes || !versionPattern.MatchString(version) || !ruleFeedSHAPattern.MatchString(manifestSHA) {
		return empty, errors.New("规则数据独立验签输入或版本绑定无效")
	}
	// Detach all input buffers before checking the signing and hash bindings.
	catalogRaw = append([]byte(nil), catalogRaw...)
	signature = append([]byte(nil), signature...)
	manifestRaw = append([]byte(nil), manifestRaw...)
	catalog, err := client.verifyCatalog(catalogRaw, signature)
	if err != nil {
		return empty, err
	}
	item, ok := Find(catalog, "network-threat-detection")
	if !ok || item.Version != version || item.SHA256 != manifestSHA {
		return empty, errors.New("规则数据不属于指定的已签名应用版本和摘要")
	}
	manifest, err := client.verifyManifestData(item, manifestRaw)
	if err != nil {
		return empty, err
	}
	for _, feed := range manifest.RuleFeeds {
		if feed.ID == feedID {
			return RuleFeedAuthority{manifest: manifest, feedID: feedID, baseURL: client.BaseURL, keySHA: hashRuleFeedFile(client.PublicKey), verified: true}, nil
		}
	}
	return empty, errors.New("规则数据未被该已签名应用声明")
}

func (client *Client) FetchVerifiedRuleFeed(ctx context.Context, authority RuleFeedAuthority) (*rulefeed.Bundle, error) {
	if client == nil || len(client.PublicKey) != 32 || !authority.verified || authority.baseURL != client.BaseURL || authority.keySHA != hashRuleFeedFile(client.PublicKey) {
		return nil, errors.New("规则数据没有本仓库和受信公钥的独立验签授权")
	}
	return client.FetchRuleFeed(ctx, authority.manifest, authority.feedID)
}

var ruleFeedIDPattern = regexp.MustCompile(`^et-open-web-[0-9]{8}$`)
var ruleFeedSHAPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ruleFeedFileLimits = map[string]int{"manifest.json": 32 << 10, "LICENSE": 128 << 10, "BSD-License.txt": 128 << 10, "classification.config": 128 << 10, "reference.config": 128 << 10, "et-open.rules": 8 << 20}

func validateRuleFeeds(manifest Manifest) error {
	if manifest.RuleDataChannel != nil {
		if manifest.ID != "network-threat-detection" || manifest.Delivery.Provider != "panel-module" || manifest.Delivery.Target != manifest.ID || len(manifest.RuleFeeds) != 0 || *manifest.RuleDataChannel != (RuleDataChannel{ID: ruleDataChannelID, Format: 1, Engine: "suricata-8.0"}) {
			return errors.New("规则数据通道须由网络威胁检测声明固定 ABI，且不能同时声明内嵌规则")
		}
		return nil
	}
	if len(manifest.RuleFeeds) == 0 {
		return nil
	}
	if len(manifest.RuleFeeds) != 1 || manifest.ID != "network-threat-detection" || manifest.Delivery.Provider != "panel-module" || manifest.Delivery.Target != manifest.ID || !versionPattern.MatchString(manifest.Version) {
		return errors.New("规则数据只能由网络威胁检测的已签名应用包声明")
	}
	feed := manifest.RuleFeeds[0]
	if !ruleFeedIDPattern.MatchString(feed.ID) || !ruleFeedSHAPattern.MatchString(feed.ManifestSHA256) || len(feed.Assets) != len(ruleFeedFileLimits) {
		return errors.New("规则数据身份或闭合文件集合无效")
	}
	if _, err := time.Parse("20060102", strings.TrimPrefix(feed.ID, "et-open-web-")); err != nil {
		return errors.New("规则数据版本日期无效")
	}
	seen := map[string]bool{}
	for _, asset := range feed.Assets {
		limit, ok := ruleFeedFileLimits[asset.Name]
		if !ok || seen[asset.Name] || asset.Bytes < 1 || asset.Bytes > limit || !ruleFeedSHAPattern.MatchString(asset.SHA256) || asset.Name == "manifest.json" && asset.SHA256 != feed.ManifestSHA256 {
			return errors.New("规则数据文件重复、未知、超限或摘要不符")
		}
		seen[asset.Name] = true
	}
	return nil
}

// FetchRuleFeed must only receive a manifest returned by FetchManifest after
// its binding to the verified signed catalog. It uses closed same-repository
// paths, downloads only a requested dataset, validates all data and performs no
// installation, native preparation, activation or capture. The root installer
// must independently verify that signing authority before adopting these bytes.
func (client *Client) FetchRuleFeed(ctx context.Context, manifest Manifest, feedID string) (*rulefeed.Bundle, error) {
	if client == nil || client.HTTP == nil {
		return nil, errors.New("规则数据仓库连接未初始化")
	}
	if err := validateRuleFeeds(manifest); err != nil {
		return nil, err
	}
	var selected *RuleFeed
	for i := range manifest.RuleFeeds {
		if manifest.RuleFeeds[i].ID == feedID {
			selected = &manifest.RuleFeeds[i]
		}
	}
	if selected == nil {
		return nil, errors.New("规则数据不在该已签名应用包中")
	}
	files := map[string][]byte{}
	// A caller-supplied HTTP client may normally follow redirects or have a
	// session cookie jar. Neither may widen this asset's repository scope. Clone
	// rather than changing shared clients used by other in-flight operations.
	transport := *client.HTTP
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	guarded := &Client{BaseURL: client.BaseURL, HTTP: &transport}
	for _, asset := range selected.Assets {
		url := fmt.Sprintf("%s/dist/apps/%s/%s/rules/%s/%s", client.BaseURL, manifest.ID, manifest.Version, selected.ID, asset.Name)
		data, err := guarded.get(ctx, url, int64(asset.Bytes))
		if err != nil {
			return nil, err
		}
		files[asset.Name] = data
	}
	return verifyRuleFeedFiles(ctx, *selected, files)
}

func verifyRuleFeedFiles(ctx context.Context, selected RuleFeed, files map[string][]byte) (*rulefeed.Bundle, error) {
	if len(files) != len(selected.Assets) {
		return nil, errors.New("规则数据不是已签名的闭合文件集合")
	}
	for _, asset := range selected.Assets {
		data, ok := files[asset.Name]
		if !ok || len(data) != asset.Bytes || hashRuleFeedFile(data) != asset.SHA256 {
			return nil, errors.New("规则数据大小或 SHA-256 与已签名应用包不符")
		}
	}
	return rulefeed.VerifyBundle(ctx, files, selected.ManifestSHA256)
}
