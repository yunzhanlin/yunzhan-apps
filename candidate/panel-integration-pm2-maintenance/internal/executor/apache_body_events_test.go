package executor

import (
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"strings"
	"testing"
)

func apacheBodyNumericEventFixture() string {
	return fmt.Sprintf(`{"time_us":1791673200123456,"engine":%q,"site_id":%q,"rule_id":941100,"phase":2,"severity":2,"mode":"block","blocked":true}`, apacheBodyEngineVersion, strings.Repeat("a", 32))
}

func TestApacheBodyNumericEventClosedSchemaAndPrivacy(t *testing.T) {
	if apacheBodyEngineVersion != core.ApacheBodyMetadataEngine {
		t.Fatal("Core numeric report accepts a different engine than the native writer")
	}
	valid := apacheBodyNumericEventFixture()
	event, ok := parseApacheBodyEvent([]byte(valid))
	if !ok || event.Time != "2026-10-10T23:00:00.123456Z" || event.RuleID != 941100 || event.Phase != 2 || event.Mode != "block" || !event.Intercepted {
		t.Fatal(event, ok)
	}
	for _, line := range []string{
		valid + "\n", valid + "\r", valid + "\x00", valid + `{}`, "[]", "null",
		strings.Replace(valid, `"rule_id":941100`, `"rule_id":941100,"RULE_ID":1`, 1),
		strings.Replace(valid, `"rule_id":941100`, `"rule_id":941100,"rule_id":1`, 1),
		strings.Replace(valid, `"phase":2`, `"phase":6`, 1),
		strings.Replace(valid, `"severity":2`, `"severity":8`, 1),
		strings.Replace(valid, `"severity":2,`, "", 1),
		strings.Replace(valid, `"blocked":true`, `"blocked":null`, 1),
		strings.Replace(valid, `"blocked":true`, `"blocked":1`, 1),
		strings.Replace(valid, `"mode":"block"`, `"mode":"observe"`, 1),
		strings.Replace(valid, `"rule_id":941100`, `"rule_id":100000000`, 1),
		strings.Replace(valid, `"rule_id":941100`, `"rule_id":0`, 1),
		strings.Replace(valid, `"rule_id":941100`, `"rule_id":1.5`, 1),
		strings.Replace(valid, `"phase":2`, `"phase":{"private":"payload"}`, 1),
		strings.Replace(valid, apacheBodyEngineVersion, "2.9.15-yz4", 1),
		strings.Replace(valid, `1791673200123456`, `0`, 1),
		strings.Replace(valid, `1791673200123456`, `253402300800000000`, 1),
		strings.Replace(valid, strings.Repeat("a", 32), "a.localhost", 1),
		strings.Replace(valid, `"mode":"block"`, `"mode":"off"`, 1),
		strings.TrimSuffix(valid, "}") + `,"request":"private-payload","cookie":"session-secret"}`,
		strings.Repeat("a", 256),
	} {
		if out, ok := parseApacheBodyEvent([]byte(line)); ok || out.Time != "" {
			t.Fatal("ambiguous/private/old/incomplete event accepted", line)
		}
	}
	observe := strings.Replace(strings.Replace(valid, `"mode":"block"`, `"mode":"observe"`, 1), `"blocked":true`, `"blocked":false`, 1)
	if event, ok := parseApacheBodyEvent([]byte(observe)); !ok || event.Intercepted || event.Mode != "observe" {
		t.Fatal("valid observation record rejected", event, ok)
	}
	data, err := json.Marshal(event)
	if err != nil || strings.Contains(string(data), `"blocked"`) || strings.Contains(string(data), `"ip"`) || strings.Contains(string(data), `"request"`) || strings.Contains(string(data), "private-payload") {
		t.Fatal("numeric event exported request context or HTTP block count", err, string(data))
	}
}
