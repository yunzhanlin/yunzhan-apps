package core

import (
	"fmt"
	"strings"
	"testing"
)

func TestApacheNumericAutomationClosedBoundsAndScalarTypes(t *testing.T) {
	valid := `{"expected_revision":0,"enabled":false,"rotate_mib":16,"max_age_minutes":60}`
	for _, raw := range []string{valid, strings.Replace(valid, `"enabled":false`, `"enabled":true`, 1), `{"expected_revision":1000000000,"enabled":true,"rotate_mib":28,"max_age_minutes":1440}`, `{"expected_revision":1,"enabled":false,"rotate_mib":1,"max_age_minutes":10}`} {
		if _, err := DecodeApacheNumericLogMaintenance([]byte(raw), "automatic-configure"); err != nil {
			t.Fatal(raw, err)
		}
	}
	bad := []string{"null", "[]", "{}", valid + " {}", strings.Repeat(" ", 4097)}
	for field, values := range map[string][]string{"expected_revision": {"-1", "1000000001", "18446744073709551615", "0.0", "null", "true", `"0"`}, "enabled": {"null", "1", `"true"`}, "rotate_mib": {"0", "29", "1.5", "null"}, "max_age_minutes": {"9", "1441", "60.0", "null"}} {
		for _, value := range values {
			values := map[string]string{"expected_revision": "0", "enabled": "false", "rotate_mib": "16", "max_age_minutes": "60"}
			values[field] = value
			bad = append(bad, fmt.Sprintf(`{"expected_revision":%s,"enabled":%s,"rotate_mib":%s,"max_age_minutes":%s}`, values["expected_revision"], values["enabled"], values["rotate_mib"], values["max_age_minutes"]))
		}
	}
	bad = append(bad, strings.Replace(valid, `"enabled":false`, `"enabled":false,"en\u0061bled":true`, 1), strings.Replace(valid, `"enabled"`, `"Enabled"`, 1), strings.TrimSuffix(valid, "}")+`,"path":"/var/log/auth.log"}`)
	for _, raw := range bad {
		if _, err := DecodeApacheNumericLogMaintenance([]byte(raw), "automatic-configure"); err == nil {
			t.Fatal("unsafe configuration accepted", raw)
		}
	}
	sha := strings.Repeat("a", 64)
	retain := `{"sha256":"` + sha + `","confirm_unknown":true}`
	if _, err := DecodeApacheNumericLogMaintenance([]byte(retain), "automatic-retain"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{valid, strings.Replace(retain, "true", "false", 1), strings.Replace(retain, "true", `true,"confirm_unknown":true`, 1)} {
		if _, err := DecodeApacheNumericLogMaintenance([]byte(raw), "automatic-retain"); err == nil {
			t.Fatal("unsafe retention accepted", raw)
		}
	}
}
