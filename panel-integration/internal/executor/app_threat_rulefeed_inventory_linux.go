//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
)

// A read-only inventory rechecks original signing authority and all assets;
// missing, failed, expired or edited entries never become known zero threats.
func (store threatIDSRuleFeedStore) inventory(ctx context.Context) core.NetworkIDSRuleFeedInventory {
	out := core.NetworkIDSRuleFeedInventory{Rows: []core.NetworkIDSRuleFeedStored{}}
	if ruleFeedStoreParents(store.base) != nil || ruleFeedStoreOwned(store.base, true, 0755) != nil {
		out.Error = "规则数据根目录身份不能核对"
		return out
	}
	root, err := os.OpenRoot(store.base)
	if err != nil {
		out.Error = "规则数据根目录不能读取"
		return out
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		out.Error = "规则数据目录不能列出"
		return out
	}
	entries, err := dir.ReadDir(9)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 8 {
		out.Error = "规则数据目录读取中断或超过 8 份预算"
		return out
	}
	out.StateKnown = true
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			out.StateKnown = false
			out.Error = "规则数据清单核对中断"
			return out
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".stage-") && core.ValidID(strings.TrimPrefix(name, ".stage-")) && ruleFeedStoreOwned(filepath.Join(store.base, name), true, 0700) == nil {
			out.RetainedStages++
			continue
		}
		if !threatIDSRuleFeedPublished.MatchString(name) {
			out.StateKnown = false
			out.Error = "规则数据目录含未知条目；未接管或清理"
			continue
		}
		row := core.NetworkIDSRuleFeedStored{State: "unverified"}
		inspect := func() error {
			if err := ruleFeedStoreOwned(filepath.Join(store.base, name), true, 0755); err != nil {
				return err
			}
			child, err := root.OpenRoot(name)
			if err != nil {
				return err
			}
			defer child.Close()
			raw, err := ruleFeedStoreRead(child, "provenance.json", 8192, 0600)
			var declared threatIDSRuleFeedRecord
			if err != nil || decodeThreatIDSPrivateJSON(raw, &declared) != nil {
				return errors.New("规则来源记录不可核对")
			}
			verified, err := store.read(ctx, name, declared.AppVersion, declared.AppManifestSHA)
			state := "verified-data-only"
			if err != nil {
				// Expiry is not corruption. Recheck the retained signatures and
				// complete bytes so an old trusted entry does not permanently
				// prevent downloading a NEW current dataset. It is not selectable.
				verified, err = store.readForCommittedUse(ctx, name, declared.AppVersion, declared.AppManifestSHA)
				state = "verified-retained-data"
			}
			if err != nil {
				return err
			}
			row.Selection = core.NetworkIDSRuleFeedSelection{FeedID: verified.FeedID, AppVersion: verified.AppVersion, AppManifestSHA: verified.AppManifestSHA, RuleManifestSHA: verified.RuleManifestSHA}
			row.State = state
			if state == "verified-retained-data" {
				row.Error = "原始签名和完整文件已核对，但当前启用授权已过期；仅保留，不能用于新规则选择。"
			}
			return nil
		}
		if err := inspect(); err != nil {
			out.StateKnown = false
			row.Error = "原始签名、文件、日期或来源记录不能独立核对"
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}
