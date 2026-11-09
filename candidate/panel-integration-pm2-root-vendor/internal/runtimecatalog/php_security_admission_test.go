package runtimecatalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPHPSecurityAdmissionKeepsHistoryButRejectsAffectedNewBuilds(t *testing.T) {
	before, _ := json.Marshal(PHP)
	for _, r := range PHP {
		known, ok := Find(r.ID)
		if !ok || known != r {
			t.Fatal("old manifest identity lost", r.ID)
		}
		v := PHPReleaseSecurity(r)
		if v.Status != "affected" || v.FixedVersion == "" || len(v.CVEs) != 2 || !strings.Contains(v.Message, "不会自动迁移") {
			t.Fatal(r.ID, v)
		}
		if RuntimeInstallAdmission(r) == nil {
			t.Fatal("affected build admitted", r.ID)
		}
	}
	for _, r := range PHPSecurity20261021 {
		v := PHPReleaseSecurity(r)
		if v.Status != "fixed-for-advisory" || v.FixedVersion != r.Version || RuntimeInstallAdmission(r) != nil {
			t.Fatal(r.ID, v)
		}
		altered := r
		altered.SHA256 = strings.Repeat("a", 64)
		if PHPReleaseSecurity(altered).Status != "unknown" || RuntimeInstallAdmission(altered) == nil {
			t.Fatal("substituted source gained security status")
		}
	}
	after, _ := json.Marshal(PHP)
	if string(before) != string(after) {
		t.Fatal("history modified")
	}
	if RuntimeInstallAdmission(Nginx[0]) != nil {
		t.Fatal("unrelated runtime policy changed")
	}
}

func TestPHPSecurityChoicesDoNotConflateOperationalHealthOrMigrateSites(t *testing.T) {
	choices := PHPReleaseChoices()
	if len(choices) != 8 {
		t.Fatal(len(choices))
	}
	for i, row := range choices {
		if row.InstallationAllowed != (i < 4) {
			t.Fatal(row)
		}
		if row.Security.Advisory != "https://www.php.net/archive/2026.php" {
			t.Fatal(row)
		}
	}
	unknown := PHP[0]
	unknown.ID = "php-8.2.99"
	unknown.Version = "8.2.99"
	if RuntimeInstallAdmission(unknown) == nil || PHPReleaseSecurity(unknown).Status != "unknown" {
		t.Fatal("unreviewed future source trusted")
	}
	choices[0].Security.CVEs[0] = "modified"
	if PHPReleaseChoices()[0].Security.CVEs[0] != "CVE-2026-109618" {
		t.Fatal("mutable security response aliases")
	}
}
