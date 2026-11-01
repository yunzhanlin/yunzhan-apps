//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Large synthetic retained ledgers are filesystem/deadline fixtures, never
// installation, request-replay or native commercial acceptance evidence.
func TestPM2ConfigurationUpgradeBudgetIsIndependentFromUnchangedLegacyBudget(t *testing.T) {
	s, app, _, record := pm2ConfigFixtureIntent(t)
	first, second := strings.Repeat("a", 8190), strings.Repeat("b", 8190)
	if err := s.patchPM2Environment(&app, map[string]*string{"A": &first, "B": &second, "TOKEN": nil}); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(app)
	app.Revision++
	if err := s.patchPM2Environment(&app, map[string]*string{"A": &second, "B": &first}); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(app)
	root := programQueueFixture(t)
	relative := "etc/panel/security-apps/modules/pm2-manager/configuration-transactions"
	dir := filepath.Join(root, relative)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	total := 0
	for i := 0; i < pm2ConfigIntentLimit; i++ {
		in := record.Intent
		in.ID = core.ID()
		in.Before, in.After = before, after
		in.BeforeSHA, in.AfterSHA = pm2ConfigHash(before), pm2ConfigHash(after)
		in.RequestSHA = core.Hash(in.ID)
		if err := validatePM2ConfigIntent(in); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(in)
		receipt := pm2ConfigReceipt{Format: 1, ID: in.ID, IntentSHA: pm2ConfigHash(raw), State: "rolled_back", ManifestSHA: in.BeforeSHA, FinishedAt: core.Now()}
		result, _ := json.Marshal(receipt)
		for name, data := range map[string][]byte{in.ID + ".intent.json": raw, in.ID + ".result.json": result} {
			total += len(data)
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if total <= 16<<20 || total > 64<<20 {
		t.Fatal("fixture did not cross only the original aggregate boundary", total)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := &programQueueReader{ctx: ctx, root: root, bytes: (16 << 20) - 1}
	if err := r.pm2Configurations(); err != nil {
		t.Fatal("declared PM2 retention consumed or enlarged the legacy inventory budget", err)
	}
	if r.bytes != (16<<20)-1 {
		t.Fatal("PM2 changed the pinned historical budget", r.bytes)
	}
	if err := r.unchanged(); err != nil {
		t.Fatal(err)
	}
}
