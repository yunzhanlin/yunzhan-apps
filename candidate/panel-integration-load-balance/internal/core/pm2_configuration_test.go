package core

import (
	"net/url"
	"strings"
	"testing"
)

func TestPM2ConfigurationReadQueryHasOnlyBoundedCanonicalIdentities(t *testing.T) {
	good := "resource_id=owned-project&pm2_operation_id=" + strings.Repeat("a", 32) + "&limit=128&offset=512"
	got, err := ParsePM2ConfigurationQuery(good)
	if err != nil || got.ResourceID != "owned-project" || got.Limit != 128 || got.Offset != 512 {
		t.Fatal(got, err)
	}
	if _, err = ParsePM2ConfigurationQuery(""); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"limit=-1", "limit=129", "offset=513", "offset=01", "limit=+1", "limit=1&limit=1", "limit=1&%6cimit=1", "Resource_id=owned-project", "unknown=1", "resource_id=../owned", "pm2_operation_id=x", "resource_id=", "limit=%ZZ", "limit=1;offset=2", strings.Repeat("a", 513)} {
		if _, err := ParsePM2ConfigurationQuery(raw); err == nil {
			t.Fatal("untrusted configuration query accepted", raw)
		}
	}
	if _, err = PM2ConfigurationReadInput(url.Values{"offset": {"0", "1"}}); err == nil {
		t.Fatal("duplicate direct input accepted")
	}
}

func TestPM2ConfigurationReleaseKeepsHistoricalRevisionsAndRejectsFutureAliases(t *testing.T) {
	if SoftwareImplementationVersion("pm2-manager") != PM2ConfigurationAppVersion {
		t.Fatal("configuration durability has no separate application revision")
	}
	if PM2OwnedListenerAppVersion != "7.0.4-compat8" || PM2IOAcknowledgementAppVersion != "7.0.4-compat9" || PM2ConfigurationAppVersion != PM2IOAcknowledgementAppVersion {
		t.Fatal("listener and storage acknowledgement revisions must remain exact")
	}
	for _, v := range []string{"7.0.4-compat5", "7.0.4-compat6", "7.0.4-compat7", PM2OwnedListenerAppVersion, PM2ConfigurationAppVersion} {
		if err := ValidateSoftwareUpdate("pm2-manager", v); err != nil {
			t.Fatal(v, err)
		}
	}
	for _, v := range []string{"7.0.4-compat7.0", "7.0.4-compat7-alias", "7.0.4-compat8.0", "7.0.4-compat8-alias", "7.0.4-compat9.0", "7.0.4-compat9-alias", "7.0.4-compat10", "7.0.5", "99.0.0"} {
		if err := ValidateSoftwareUpdate("pm2-manager", v); err == nil {
			t.Fatal("unimplemented alias accepted", v)
		}
	}
}
