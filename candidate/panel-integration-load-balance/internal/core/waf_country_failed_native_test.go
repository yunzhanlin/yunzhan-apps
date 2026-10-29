package core

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCountryFailedNativeRequiresWholeOriginalResultAndBothUniqueAudits(t *testing.T) {
	for _, kind := range []string{"complete", "foreign-job", "foreign-actor", "foreign-payload", "foreign-request", "different-error", "needs-attention", "cache-present", "missing-dispatch", "duplicate-dispatch", "missing-terminal-audit", "different-terminal-audit", "missing-result", "changed-result-hash"} {
		t.Run(kind, func(t *testing.T) {
			s, j, original, out := countryWorkerFixture(t)
			if _, err := s.wafCountryDispatchBoundary(context.Background(), j, true); err != nil {
				t.Fatal(err)
			}
			out.State, out.Cache, out.Error = "failed", nil, "original bounded transfer interrupted"
			raw, _ := json.Marshal(out)
			if err := s.finishWAFCountryResult(context.Background(), j, raw, original.Actor, original.Selection, nil); err != nil {
				t.Fatal(err)
			}
			before := countryWorkerState(t, s, j.ID)
			var err error
			switch kind {
			case "foreign-job":
				out.JobID = ID()
			case "foreign-actor":
				out.ActorID = ID()
			case "foreign-payload":
				out.PayloadSHA = Hash("foreign")
			case "foreign-request":
				out.RequestSHA = Hash("foreign")
			case "different-error":
				out.Error = "another outcome"
			case "needs-attention":
				out.State = "needs_attention"
			case "cache-present":
				out.Cache = &WAFCountryCacheEntry{}
			case "missing-dispatch":
				_, err = s.DB.Exec(`DELETE FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, j.ID)
			case "duplicate-dispatch":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'waf.country.dispatch',?,?,?)`, original.Actor, j.ID, original.PayloadSHA, Now())
			case "missing-terminal-audit":
				_, err = s.DB.Exec(`DELETE FROM audit_logs WHERE action='waf.country.result' AND target=?`, j.ID)
			case "different-terminal-audit":
				_, err = s.DB.Exec(`UPDATE audit_logs SET result='failed:foreign' WHERE action='waf.country.result' AND target=?`, j.ID)
			case "missing-result":
				_, err = s.DB.Exec(`DELETE FROM waf_country_results WHERE job_id=?`, j.ID)
			case "changed-result-hash":
				_, err = s.DB.Exec(`UPDATE waf_country_results SET result_sha256=? WHERE job_id=?`, Hash("foreign"), j.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = s.ValidateWAFCountryFailedNative(context.Background(), out)
			if (err == nil) != (kind == "complete") {
				t.Fatal("historical failure qualification mismatch", kind, err)
			}
			if countryWorkerState(t, s, j.ID) != before {
				t.Fatal("read-only validation changed original failure")
			}
		})
	}
}
