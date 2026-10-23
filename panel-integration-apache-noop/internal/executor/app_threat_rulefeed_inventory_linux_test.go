//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestThreatIDSRuleFeedInventoryRechecksDataAndPreservesUnknownState(t *testing.T) {
	for _, scenario := range []string{"empty", "valid", "modified", "expired", "retained-stage", "unknown-entry", "linked-stage", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			in, trust, appSHA := threatRuleFeedFixture(t, "HOME_NET")
			store := threatRuleFeedTestStore(t, trust)
			ctx := context.Background()
			if scenario != "empty" && scenario != "retained-stage" && scenario != "unknown-entry" && scenario != "linked-stage" {
				if _, err := store.install(ctx, in, "1.3.0", appSHA); err != nil {
					t.Fatal(err)
				}
			}
			name := threatIDSRuleFeedName(in.FeedID, core.Hash(string(in.Files["manifest.json"])))
			var err error
			switch scenario {
			case "modified":
				err = os.WriteFile(filepath.Join(store.base, name, "et-open.rules"), []byte("changed"), 0644)
			case "expired":
				store.now = func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }
			case "retained-stage":
				stage := filepath.Join(store.base, ".stage-"+core.ID())
				err = os.Mkdir(stage, 0700)
				if err == nil {
					err = os.Chmod(stage, 0700)
				}
			case "unknown-entry":
				err = os.WriteFile(filepath.Join(store.base, "foreign.rules"), []byte("keep"), 0600)
			case "linked-stage":
				err = os.Symlink(t.TempDir(), filepath.Join(store.base, ".stage-"+core.ID()))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			out := store.inventory(ctx)
			known := scenario == "empty" || scenario == "valid" || scenario == "expired" || scenario == "retained-stage"
			if out.StateKnown != known {
				t.Fatal("unknown inventory represented as known", scenario, out)
			}
			if scenario == "valid" && (len(out.Rows) != 1 || out.Rows[0].State != "verified-data-only" || out.Rows[0].Selection.AppManifestSHA != appSHA) {
				t.Fatal("valid data-only status missing", out)
			}
			if scenario == "modified" {
				if len(out.Rows) != 1 || out.Rows[0].State != "unverified" || out.Rows[0].Error == "" || out.Rows[0].Selection.FeedID != "" {
					t.Fatal("damaged or expired data adopted", out)
				}
			}
			if scenario == "expired" {
				if len(out.Rows) != 1 || out.Rows[0].State != "verified-retained-data" || out.Rows[0].Error == "" || out.Rows[0].Selection.AppManifestSHA != appSHA {
					t.Fatal("expiry disguised as corruption or current authorization", out)
				}
				if _, err := store.read(ctx, name, "1.3.0", appSHA); err == nil {
					t.Fatal("retained inventory renewed activation authority")
				}
			}
			if scenario == "retained-stage" && (out.RetainedStages != 1 || len(out.Rows) != 0) {
				t.Fatal("failed stage adopted or omitted", out)
			}
			if scenario == "unknown-entry" {
				if raw, err := os.ReadFile(filepath.Join(store.base, "foreign.rules")); err != nil || string(raw) != "keep" {
					t.Fatal("foreign evidence changed", err)
				}
			}
		})
	}
}
