//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
)

// Retained immutable signed catalogs are root-side anti-rollback history. A
// stale catalog is never reused as current installation authority. This does
// not prune history, accept a cursor from the API, or modify active native rules.
func (store threatIDSRuleFeedStore) channelProgress(ctx context.Context, in appcatalog.RuleFeedEnvelope, version, appSHA string) error {
	root, err := os.OpenRoot(store.base)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(9)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 8 {
		return errors.New("规则数据历史数量或读取状态无效")
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".stage-") && core.ValidID(strings.TrimPrefix(name, ".stage-")) {
			continue
		}
		if !threatIDSRuleFeedPublished.MatchString(name) || ruleFeedStoreOwned(filepath.Join(store.base, name), true, 0755) != nil {
			return errors.New("规则数据历史包含未知、链接或外国目录")
		}
		dataRoot, err := root.OpenRoot(name)
		if err != nil {
			return err
		}
		previous, err := store.readChannelHistory(dataRoot, name)
		dataRoot.Close()
		if err != nil {
			return err
		}
		if previous != nil {
			if _, err := store.trust.VerifyRuleDataAuthority(in.Catalog, in.Signature, in.AppManifest, in.DataCatalog, in.DataSignature, version, appSHA, store.now(), previous); err != nil {
				return err
			}
		}
	}
	return nil
}

func (store threatIDSRuleFeedStore) readChannelHistory(root *os.Root, name string) (*appcatalog.RuleDataAuthority, error) {
	data, err := ruleFeedStoreRead(root, "provenance.json", 8192, 0600)
	var record threatIDSRuleFeedRecord
	if err != nil || decodeThreatIDSPrivateJSON(data, &record) != nil {
		return nil, errors.New("规则数据历史来源记录损坏")
	}
	if (record.Format != 1 && record.Format != 2) || record.State != "verified-data-only" || threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA) != name {
		return nil, errors.New("规则数据历史来源格式或身份不同")
	}
	var appCatalog, appSignature, appManifest, dataCatalog, dataSignature []byte
	for _, asset := range []struct {
		name   string
		limit  int64
		digest string
		dest   *[]byte
	}{
		{"catalog.json", 2 << 20, record.CatalogSHA, &appCatalog},
		{"catalog.sig", 4096, record.SignatureSHA, &appSignature},
		{"app-manifest.json", 128 << 10, record.AppManifestSHA, &appManifest},
		{"rule-data-catalog.json", 32 << 10, record.DataCatalogSHA, &dataCatalog},
		{"rule-data-catalog.sig", 4096, record.DataSignatureSHA, &dataSignature},
	} {
		if record.Format == 1 && (asset.name == "rule-data-catalog.json" || asset.name == "rule-data-catalog.sig") {
			continue
		}
		value, err := ruleFeedStoreRead(root, asset.name, asset.limit, 0600)
		if err != nil || core.Hash(string(value)) != asset.digest {
			return nil, errors.New("规则数据历史签名原文或摘要不完整")
		}
		*asset.dest = value
	}
	if core.Hash(string(store.trust.PublicKey)) != record.TrustKeySHA {
		return nil, errors.New("规则数据历史受信密钥不同")
	}
	if record.Format == 1 {
		if record.DataCatalogSHA != "" || record.DataSignatureSHA != "" {
			return nil, errors.New("规则数据历史格式降级或含未声明通道")
		}
		// A forged 'legacy' receipt must not hide real channel history. The
		// original app signature must actually declare the inline feed.
		if _, err := store.trust.VerifyRuleFeedAuthority(appCatalog, appSignature, appManifest, record.AppVersion, record.AppManifestSHA, record.FeedID); err != nil {
			return nil, err
		}
		return nil, nil
	}
	authority, err := store.trust.VerifyRetainedRuleDataAuthority(appCatalog, appSignature, appManifest, dataCatalog, dataSignature, record.AppVersion, record.AppManifestSHA, store.now())
	if err != nil {
		return nil, err
	}
	if authority.Catalog().Feed.ID != record.FeedID || authority.Catalog().Feed.ManifestSHA256 != record.RuleManifestSHA {
		return nil, errors.New("规则数据历史原始签名与来源选择不同")
	}
	return &authority, nil
}
