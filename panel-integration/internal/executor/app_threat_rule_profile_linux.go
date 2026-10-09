//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Read-only root approval of a candidate, not activation. A published directory
// or a receipt saying 'verified' is insufficient: read rechecks the original
// pinned signatures, all six files, ownership, exact modes and freshness.
func (store threatIDSRuleFeedStore) ruleDataYAML(ctx context.Context, in threatIDSConfig, selection core.NetworkIDSRuleFeedSelection) (string, error) {
	if err := core.ValidateNetworkIDSRuleFeedSelection(selection); err != nil {
		return "", err
	}
	record, err := store.read(ctx, threatIDSRuleFeedName(selection.FeedID, selection.RuleManifestSHA), selection.AppVersion, selection.AppManifestSHA)
	if err != nil {
		return "", err
	}
	if record.FeedID != selection.FeedID || record.AppVersion != selection.AppVersion || record.AppManifestSHA != selection.AppManifestSHA || record.RuleManifestSHA != selection.RuleManifestSHA {
		return "", errors.New("IDS 规则候选与独立核对的本机数据不同")
	}
	return threatIDSRuleDataYAML(in, selection)
}

func (s *Service) verifiedThreatIDSRuleDataYAML(ctx context.Context, in threatIDSConfig, selection core.NetworkIDSRuleFeedSelection) (string, error) {
	store, err := s.threatIDSRuleFeedStore()
	if err != nil {
		return "", err
	}
	return store.ruleDataYAML(ctx, in, selection)
}

type threatIDSRuleProfileStatus struct {
	Source                 string                            `json:"source"`
	State                  string                            `json:"state"`
	Selection              *core.NetworkIDSRuleFeedSelection `json:"selection,omitempty"`
	CurrentForNewSelection bool                              `json:"current_for_new_selection"`
	AgeDays                int                               `json:"age_days"`
	Warning                string                            `json:"warning,omitempty"`
}

// Called for a committed record or validated two-file journal, never for a
// fresh caller's choice. No network, writes, unit execution or automatic switch.
func (s *Service) threatIDSCommittedRuleProfile(ctx context.Context, in threatIDSConfig) (threatIDSRuleProfileStatus, error) {
	out := threatIDSRuleProfileStatus{Source: "original", State: "fixed-indicators", CurrentForNewSelection: true}
	if in.RuleFeed == nil {
		return out, nil
	}
	selection := *in.RuleFeed
	if err := core.ValidateNetworkIDSRuleProfile(core.NetworkIDSRuleProfileSelection{Source: "verified-feed", Selection: &selection}); err != nil {
		return out, err
	}
	store, err := s.threatIDSRuleFeedStore()
	if err != nil {
		return out, err
	}
	return store.committedRuleProfile(ctx, selection)
}

func (store threatIDSRuleFeedStore) committedRuleProfile(ctx context.Context, selection core.NetworkIDSRuleFeedSelection) (threatIDSRuleProfileStatus, error) {
	var out threatIDSRuleProfileStatus
	if err := core.ValidateNetworkIDSRuleProfile(core.NetworkIDSRuleProfileSelection{Source: "verified-feed", Selection: &selection}); err != nil {
		return out, err
	}
	name := threatIDSRuleFeedName(selection.FeedID, selection.RuleManifestSHA)
	record, err := store.readForCommittedUse(ctx, name, selection.AppVersion, selection.AppManifestSHA)
	if err != nil {
		return out, err
	}
	if record.FeedID != selection.FeedID || record.RuleManifestSHA != selection.RuleManifestSHA || record.AppVersion != selection.AppVersion || record.AppManifestSHA != selection.AppManifestSHA {
		return out, errors.New("已提交规则与独立核对的来源不同")
	}
	date, err := time.Parse("20060102", strings.TrimPrefix(record.FeedID, "et-open-web-"))
	if err != nil {
		return out, err
	}
	out = threatIDSRuleProfileStatus{Source: "verified-feed", State: "verified-for-committed-use", Selection: &selection, AgeDays: int(store.now().UTC().Sub(date) / (24 * time.Hour)), CurrentForNewSelection: store.now().UTC().Before(date.Add(14 * 24 * time.Hour))}
	if record.Format == 2 {
		root, err := os.OpenRoot(filepath.Join(store.base, name))
		if err != nil {
			return threatIDSRuleProfileStatus{}, err
		}
		defer root.Close()
		raw, err := ruleFeedStoreRead(root, "rule-data-catalog.json", 32<<10, 0600)
		var data appcatalog.RuleDataCatalog
		if err != nil || core.Hash(string(raw)) != record.DataCatalogSHA || json.Unmarshal(raw, &data) != nil {
			return threatIDSRuleProfileStatus{}, errors.New("规则核对后目录原文已改变")
		}
		expires, err := time.Parse(time.RFC3339, data.ExpiresAt)
		if err != nil {
			return threatIDSRuleProfileStatus{}, err
		}
		out.CurrentForNewSelection = out.CurrentForNewSelection && store.now().UTC().Before(expires)
	}
	if !out.CurrentForNewSelection {
		out.Warning = "当前规则的签名和完整文件已重新核对，但更新授权已过期或数据已超过维护窗口。保留已提交选择，不自动切换；新启用其他数据须检查最新签名目录。"
	}
	return out, nil
}
