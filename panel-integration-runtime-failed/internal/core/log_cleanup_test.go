package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLogCleanupRequestRejectsAmbiguousOrIncompleteJSON(t *testing.T) {
	v := LogCleanupRequest{RequestID: ID(), SiteID: ID(), RetentionDays: 2}
	body, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var parsed LogCleanupRequest
	if e = json.Unmarshal(body, &parsed); e != nil || parsed != v {
		t.Fatal(parsed, e)
	}
	valid := string(body)
	for _, bad := range []string{`null`, `{}`, strings.Replace(valid, `"attempt":0`, `"attempt":null`, 1), strings.Replace(valid, `"attempt":0`, `"attempt":0,"attempt":1`, 1), strings.Replace(valid, `"attempt":0,`, ``, 1), strings.Replace(valid, `"attempt":0`, `"Attempt":0`, 1), strings.Replace(valid, `"retention_days":2`, `"retention_days":101`, 1), valid + `{}`} {
		if json.Unmarshal([]byte(bad), &parsed) == nil {
			t.Fatal("ambiguous request accepted", bad)
		}
	}
}

func TestLogCleanupContinueRequestRequiresExplicitUnknownAcknowledgmentAndPlanDigest(t *testing.T) {
	v := LogCleanupContinueRequest{RequestID: ID(), SiteID: ID(), PlanSHA256: Hash("fixed-plan"), AcknowledgeUnknown: true}
	body, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var parsed LogCleanupContinueRequest
	if e = json.Unmarshal(body, &parsed); e != nil || parsed != v {
		t.Fatal(parsed, e)
	}
	valid := string(body)
	for _, bad := range []string{`{}`, `null`, valid + `{}`, strings.Replace(valid, `"acknowledge_unknown":true`, `"acknowledge_unknown":false`, 1), strings.Replace(valid, `"acknowledge_unknown":true`, `"acknowledge_unknown":null`, 1), strings.Replace(valid, `"acknowledge_unknown":true`, `"acknowledge_unknown":true,"acknowledge_unknown":true`, 1), strings.Replace(valid, v.PlanSHA256, strings.ToUpper(v.PlanSHA256), 1), strings.Replace(valid, `"plan_sha256"`, `"Plan_SHA256"`, 1)} {
		if json.Unmarshal([]byte(bad), &parsed) == nil {
			t.Fatal("ambiguous continuation accepted", bad)
		}
	}
}

func TestLogCleanupResultRequiresConsistentOwnedUniqueArchiveList(t *testing.T) {
	id := ID()
	file := "panel-" + id + ".access.log.20260801-010000"
	v := LogCleanupResult{Rotated: 1, Deleted: 1, DeletedBytes: 42, Files: []string{file}}
	body, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var parsed LogCleanupResult
	if e = json.Unmarshal(body, &parsed); e != nil {
		t.Fatal(e)
	}
	valid := string(body)
	for _, bad := range []string{`{}`, `{"rotated":0,"deleted":0,"deleted_bytes":1,"files":[]}`, strings.Replace(valid, `"deleted":1`, `"deleted":2`, 1), strings.Replace(valid, `"rotated":1`, `"rotated":1,"rotated":2`, 1), strings.Replace(valid, file, `../../foreign.log`, 1), strings.Replace(valid, `20260801-010000`, `20260230-010000`, 1), strings.Replace(valid, `"files":["`+file+`"]`, `"files":null`, 1)} {
		if json.Unmarshal([]byte(bad), &parsed) == nil {
			t.Fatal("invalid result accepted", bad)
		}
	}
}
