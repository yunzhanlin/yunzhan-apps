package core

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func countryOperationFixture() WAFCountryDataOperation {
	in := countryDataSelectionFixture()
	id, actor := ID(), ID()
	payload, _ := json.Marshal(in)
	out := WAFCountryDataOperation{Format: 1, JobID: id, ActorID: actor, Selection: in, PayloadSHA: Hash(string(payload)), RequestSHA: Hash("synthetic sealed original Root request"), RequestedCachePlanSHA: WAFCountryCachePlanSHA(id, in), State: "succeeded", DataOnly: true}
	out.Cache = &WAFCountryCacheEntry{Dataset: WAFCountryCacheDataset(in), DataManifestSHA: in.DataManifestSHA, Countries: append([]string(nil), in.Countries...), Release: in.Release, Revision: in.Revision, OriginalJobID: id, PlanSHA: WAFCountryCachePlanSHA(id, in), PreparedAt: "2026-10-20T00:00:00Z", Bytes: 400, Networks: 2, Published: true}
	return out
}

func TestWAFCountryOperationBindsOriginalAndIndependentReuseWithoutClaimingActivePolicy(t *testing.T) {
	out := countryOperationFixture()
	for _, state := range []string{"queued", "running", "succeeded", "failed", "needs_attention"} {
		v := out
		v.State = state
		if state != "succeeded" {
			v.Cache = nil
		}
		if state == "failed" || state == "needs_attention" {
			v.Error = "synthetic original interruption"
		}
		raw, _ := json.Marshal(v)
		got, err := DecodeWAFCountryDataOperation(raw, out.JobID, out.ActorID, out.Selection)
		if err != nil || !reflect.DeepEqual(got, v) {
			t.Fatal(state, got, err)
		}
	}
	reuse := out
	cache := *out.Cache
	cache.OriginalJobID = ID()
	cache.PlanSHA = WAFCountryCachePlanSHA(cache.OriginalJobID, out.Selection)
	cache.Reused = true
	reuse.Cache = &cache
	raw, _ := json.Marshal(reuse)
	got, err := DecodeWAFCountryDataOperation(raw, out.JobID, out.ActorID, out.Selection)
	if err != nil || !got.Cache.Reused || got.Cache.OriginalJobID == out.JobID {
		t.Fatal("immutable data reuse lost original publisher identity", got, err)
	}
	if WAFCountryCacheDataset(out.Selection) != out.Selection.DataManifestSHA+"-"+Hash(`["CN","US"]`) {
		t.Fatal("dataset ID differs from Root canonical selection")
	}
}

func TestWAFCountryOperationRejectsPartialForeignActiveReplayingAndMalformedReplies(t *testing.T) {
	out := countryOperationFixture()
	for _, kind := range []string{"job", "actor", "payload", "request", "plan", "active", "not-published", "reused", "original-job", "original-plan", "data", "countries", "release", "revision", "bytes", "networks", "time", "data-only", "replay", "unknown-state", "missing-cache"} {
		t.Run(kind, func(t *testing.T) {
			v := out
			cache := *out.Cache
			v.Cache = &cache
			switch kind {
			case "job":
				v.JobID = ID()
			case "actor":
				v.ActorID = ID()
			case "payload":
				v.PayloadSHA = Hash("foreign")
			case "request":
				v.RequestSHA = ""
			case "plan":
				v.RequestedCachePlanSHA = Hash("other plan")
			case "active":
				cache.ActivatedNginxPolicy = true
			case "not-published":
				cache.Published = false
			case "reused":
				cache.Reused = true
			case "original-job":
				cache.OriginalJobID = ""
			case "original-plan":
				cache.PlanSHA = Hash("partial")
			case "data":
				cache.DataManifestSHA = Hash("other manifest")
			case "countries":
				cache.Countries = []string{"US"}
			case "release":
				cache.Release = "2026-11"
			case "revision":
				cache.Revision++
			case "bytes":
				cache.Bytes = 64<<20 + 1
			case "networks":
				cache.Networks = 1<<20 + 1
			case "time":
				cache.PreparedAt = "2026-10-20T00:00:00+00:00"
			case "data-only":
				v.DataOnly = false
			case "replay":
				v.AutomaticReplayAllowed = true
			case "unknown-state":
				v.State = "active"
			case "missing-cache":
				v.Cache = nil
			}
			raw, _ := json.Marshal(v)
			if got, err := DecodeWAFCountryDataOperation(raw, out.JobID, out.ActorID, out.Selection); err == nil || !reflect.DeepEqual(got, WAFCountryDataOperation{}) {
				t.Fatal("unqualified reply accepted", got, err)
			}
		})
	}
	raw, _ := json.Marshal(out)
	for _, bad := range []string{string(raw) + ` {}`, strings.Replace(string(raw), `"format":1`, `"format":1,"format":1`, 1), strings.Replace(string(raw), `"format":1`, `"Format":1`, 1), strings.Replace(string(raw), `"data_only":true`, `"data_only":null`, 1), strings.Replace(string(raw), `"published":true`, `"published":true,"published":true`, 1), strings.Replace(string(raw), `"published":true`, `"Published":true`, 1), strings.Replace(string(raw), `"action":"download"`, `"action":"download","action":"download"`, 1), strings.TrimSuffix(string(raw), "}") + `,"source":"https://evil.invalid"}`} {
		if got, err := DecodeWAFCountryDataOperation([]byte(bad), out.JobID, out.ActorID, out.Selection); err == nil || !reflect.DeepEqual(got, WAFCountryDataOperation{}) {
			t.Fatal("malformed Root reply accepted", got, err)
		}
	}
}
