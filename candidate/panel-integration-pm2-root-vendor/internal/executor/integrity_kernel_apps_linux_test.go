//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestIntegrityKernelOriginalApplicationJSONRejectsEmptyAliasAndForeignFormat(t *testing.T) {
	_, request, plan, _ := integrityKernelFixture(t)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded core.IntegrityKernelRequest
	if err = integrityKernelJSON(raw, &decoded); err != nil || decoded != request {
		t.Fatal("unchanged original website request is unreadable", err)
	}
	for _, field := range []string{`"app_id":""`, `"app_id":null`, `"AppID":"enterprise-tamper-proof"`, `"app_id":"enterprise-tamper-proof"`} {
		bad := []byte(strings.TrimSuffix(string(raw), "}") + "," + field + "}")
		if err = integrityKernelJSON(bad, &decoded); err == nil {
			t.Fatal("explicit application alias changed a format1 original", string(bad))
		}
	}
	enterprise := core.NewIntegrityKernelApplicationRequest(core.IntegrityKernelEnterpriseApplication, request)
	raw, _ = json.Marshal(enterprise)
	if err = integrityKernelJSON(raw, &decoded); err != nil || core.ValidateIntegrityKernelRequest(decoded) != nil {
		t.Fatal("exact enterprise request was rejected", err)
	}
	plan.Format, plan.AppID = 1, core.IntegrityKernelEnterpriseApplication
	if validateIntegrityKernelPlan(plan) == nil {
		t.Fatal("a website inode plan borrowed the enterprise application")
	}
	plan.Format = 2
	if err = validateIntegrityKernelPlan(plan); err != nil {
		t.Fatal("exact enterprise inode plan was rejected", err)
	}
}

func TestIntegrityKernelEnterpriseOnlyUsesOnePrivateJournalWithoutWebsiteInstallation(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	enterpriseReceipt := filepath.Join(s.moduleDir(core.IntegrityKernelEnterpriseApplication), "installed.json")
	before, err := os.ReadFile(enterpriseReceipt)
	if err != nil {
		t.Fatal(err)
	}
	// Only this unit test's disposable placeholder directory is removed.
	if err = os.RemoveAll(s.moduleDir(core.IntegrityKernelWebsiteApplication)); err != nil {
		t.Fatal(err)
	}
	d, err := s.integrityKernelStore(true)
	if err != nil {
		t.Fatal("enterprise-only installation cannot create its shared private journal", err)
	}
	d.Close()
	if _, err = os.Lstat(filepath.Join(s.moduleDir(core.IntegrityKernelWebsiteApplication), "installed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("creating a shared journal fabricated a website application installation", err)
	}
	after, err := os.ReadFile(enterpriseReceipt)
	if err != nil || string(before) != string(after) {
		t.Fatal("original enterprise receipt was changed", err)
	}
	ids, err := s.integrityKernelOperationIDs()
	if err != nil || len(ids) != 0 {
		t.Fatal("shared journal was not empty", ids, err)
	}
	anchor, err := s.moduleRecordDirectory(core.IntegrityKernelWebsiteApplication)
	if err != nil {
		t.Fatal("shared anchor fails the original Root-private directory checks", err)
	}
	anchor.Close()
}

func TestIntegrityKernelEnterpriseSharedAnchorRejectsLegacySymlink(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	legacy := s.moduleDir(core.IntegrityKernelWebsiteApplication)
	if err := os.RemoveAll(legacy); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, legacy); err != nil {
		t.Fatal(err)
	}
	if d, err := s.integrityKernelStore(true); err == nil {
		d.Close()
		t.Fatal("enterprise anchor followed an existing symlink")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatal("symlink target received a private journal", entries, err)
	}
}
