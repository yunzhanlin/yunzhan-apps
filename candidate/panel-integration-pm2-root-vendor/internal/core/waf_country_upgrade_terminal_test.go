package core

import (
	"context"
	"encoding/json"
	"testing"
)

func TestWAFCountryUpgradeTerminalLabelCannotHideMissingForeignOrAlteredOriginal(t *testing.T) {
	for _, kind := range []string{"label-only-success", "empty-failure", "payload-hash", "duplicate-queue-audit", "result-hash", "foreign-result-actor", "result-alias", "result-text-type"} {
		t.Run(kind, func(t *testing.T) {
			s, j, original, out := countryWorkerFixture(t)
			raw, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.finishWAFCountryResult(context.Background(), j, raw, original.Actor, original.Selection, nil); err != nil {
				t.Fatal(err)
			}
			if err := s.CheckWAFCountryUpgrade(context.Background()); err != nil {
				t.Fatal("complete original fixture rejected", err)
			}
			switch kind {
			case "label-only-success":
				_, err = s.DB.Exec(`DELETE FROM waf_country_results WHERE job_id=?`, j.ID)
			case "empty-failure":
				_, err = s.DB.Exec(`DELETE FROM waf_country_results WHERE job_id=?; UPDATE runtime_jobs SET state='failed',error='' WHERE id=?`, j.ID, j.ID)
			case "payload-hash":
				_, err = s.DB.Exec(`UPDATE waf_country_requests SET payload_sha256=? WHERE job_id=?`, Hash("changed original"), j.ID)
			case "duplicate-queue-audit":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.queue',?,'queued',?)`, original.Actor, j.ID, Now())
			case "result-hash":
				_, err = s.DB.Exec(`UPDATE waf_country_results SET result_sha256=? WHERE job_id=?`, Hash("foreign complete reply"), j.ID)
			case "foreign-result-actor":
				out.ActorID = ID()
				raw, err = json.Marshal(out)
				if err == nil {
					_, err = s.DB.Exec(`UPDATE waf_country_results SET body=?,result_sha256=? WHERE job_id=?`, raw, Hash(string(raw)), j.ID)
				}
			case "result-alias":
				raw = append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"STATE":"succeeded"}`)...)
				_, err = s.DB.Exec(`UPDATE waf_country_results SET body=?,result_sha256=? WHERE job_id=?`, raw, Hash(string(raw)), j.ID)
			case "result-text-type":
				_, err = s.DB.Exec(`UPDATE waf_country_results SET body=CAST(body AS TEXT) WHERE job_id=?`, j.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.CheckWAFCountryUpgrade(context.Background()) == nil {
				t.Fatal("partial, foreign or forged original completion accepted", kind)
			}
			var state string
			if s.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, j.ID).Scan(&state) != nil || state != "succeeded" && kind != "empty-failure" || state != "failed" && kind == "empty-failure" {
				t.Fatal("upgrade observation rewrote original terminal", state)
			}
		})
	}
}
