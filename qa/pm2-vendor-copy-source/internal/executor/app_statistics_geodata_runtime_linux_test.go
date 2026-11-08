//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestStatisticsGeoInstalledEpochRequiredAndOldRecordPreserved(t *testing.T) {
	f := geoStoreRootFixture(t)
	base := filepath.Dir(f.store.base)
	security := filepath.Join(base, "security")
	dir := filepath.Join(security, "modules", "website-statistics-v2")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := New(Config{SecurityDir: security, SystemRoot: "/"})
	path := filepath.Join(dir, "installed.json")
	old := map[string]any{"id": "website-statistics-v2", "version": "2.5.0", "installed_at": "2026-01-01T00:00:00Z", "settings": map[string]any{"owned": "preserved"}}
	raw, _ := json.Marshal(old)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.statisticsGeoInstance(); err == nil {
		t.Fatal("old2.5 implicitly opted into geography")
	}
	s.refreshStatisticsGeoCache(context.Background())
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("binary/cache startup changed old app record")
	}
	next := map[string]any{}
	for k, v := range old {
		next[k] = v
	}
	next["version"] = "2.6.0"
	bad, _ := json.Marshal(next)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.moduleInstalledRecord("website-statistics-v2"); err == nil {
		t.Fatal("unbound2.6 installed record accepted")
	}
	next["installation_id"] = strings.Repeat("a", 32)
	good, _ := json.Marshal(next)
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	instance, err := s.statisticsGeoInstance()
	if err != nil || instance != next["installation_id"] {
		t.Fatal(instance, err)
	}
	if _, err := validateStatisticsNextInstalled(good); err != nil {
		t.Fatal("new fixed candidate rejected", err)
	}
	old["installation_id"] = strings.Repeat("b", 32)
	wrong, _ := json.Marshal(old)
	if _, err := validateStatisticsNextInstalled(wrong); err == nil {
		t.Fatal("old version carried new instance epoch")
	}
}
func TestStatisticsGeoPrivateJobCodecNoAliasNullOrOtherSchema(t *testing.T) {
	r := statisticsGeoRequest{Format: 1, JobID: strings.Repeat("a", 32), Selection: core.StatisticsGeoSelection{Action: "install", AppVersion: "2.6.0", AppManifestSHA: strings.Repeat("b", 64), InstallationID: strings.Repeat("c", 32), Release: "2026-10", DataManifestSHA: strings.Repeat("d", 64)}, EnvelopeSHA: strings.Repeat("e", 64)}
	raw, _ := json.Marshal(r)
	var out statisticsGeoRequest
	if err := decodeStatisticsGeoPrivate(raw, &out); err != nil || out != r {
		t.Fatal(out, err)
	}
	for _, bad := range []string{`{"format":1,` + string(raw[1:]), strings.Replace(string(raw), `"job_id"`, `"Job_Id"`, 1), strings.Replace(string(raw), `"selection":{`, `"selection":null,"unused":{`, 1), string(raw) + ` {}`} {
		if decodeStatisticsGeoPrivate([]byte(bad), &out) == nil {
			t.Fatal("ambiguous private job accepted", bad)
		}
	}
}
