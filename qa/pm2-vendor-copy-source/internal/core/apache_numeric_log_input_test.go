package core

import (
	"strings"
	"testing"
)

func TestApacheNumericLogMaintenanceClosedScalars(t *testing.T) {
	sha := strings.Repeat("a", 64)
	good := map[string][]string{
		"rotate":       {"{}", " { } "},
		"remove":       {`{"sha256":"` + sha + `","confirm_delete":true}`},
		"retain":       {`{"index_sha256":"` + sha + `","snapshot_sha256":"","snapshot_missing":true,"confirm_unknown":true}`, `{"index_sha256":"` + sha + `","snapshot_sha256":"` + sha + `","snapshot_missing":false,"confirm_unknown":true}`},
		"retain-stage": {`{"sha256":"` + sha + `","confirm_unknown":true}`},
	}
	for kind, values := range good {
		for _, raw := range values {
			if _, err := DecodeApacheNumericLogMaintenance([]byte(raw), kind); err != nil {
				t.Fatal(kind, raw, err)
			}
		}
	}
	valid := good["remove"][0]
	bad := []string{"null", "[]", "{}", valid + " {}", strings.Repeat(" ", 4097), strings.Replace(valid, sha, strings.ToUpper(sha), 1), strings.Replace(valid, `"sha256"`, `"SHA256"`, 1), strings.Replace(valid, `"confirm_delete":true`, `"confirm_delete":false,"confirm_delete":true`, 1), strings.Replace(valid, `"confirm_delete":true`, `"confirm_delete":true,"confirm_\u0064elete":true`, 1), strings.Replace(valid, `"confirm_delete":true`, `"confirm_delete":null`, 1), strings.Replace(valid, `"confirm_delete":true`, `"confirm_delete":"true"`, 1), strings.TrimSuffix(valid, "}") + `,"path":"/etc/shadow"}`}
	for _, raw := range bad {
		if _, err := DecodeApacheNumericLogMaintenance([]byte(raw), "remove"); err == nil {
			t.Fatal("unsafe maintenance accepted", raw)
		}
	}
	for _, raw := range good["retain"] {
		for _, kind := range []string{"rotate", "remove", "retain-stage", "unknown"} {
			if _, err := DecodeApacheNumericLogMaintenance([]byte(raw), kind); err == nil {
				t.Fatal("cross-operation confirmation accepted", kind)
			}
		}
	}
	if _, err := DecodeApacheNumericLogMaintenance([]byte(strings.Replace(good["retain"][0], `"snapshot_missing":true`, `"snapshot_missing":false`, 1)), "retain"); err == nil {
		t.Fatal("missing state and digest contradiction")
	}
}
