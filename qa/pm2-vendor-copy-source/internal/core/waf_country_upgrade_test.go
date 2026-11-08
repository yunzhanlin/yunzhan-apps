package core

import (
	"context"
	"encoding/json"
	"testing"
)

func TestWAFCountryUpgradeRefusesUnknownCoreTaskEvenWithoutRootJournal(t *testing.T) {
	for _, state := range []string{"queued", "running", "needs_attention", "unrecognized"} {
		t.Run(state, func(t *testing.T) {
			s, j, _, _ := countryWorkerFixture(t)
			if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state=? WHERE id=?`, state, j.ID); err != nil {
				t.Fatal(err)
			}
			if s.CheckWAFCountryUpgrade(context.Background()) == nil || countryWorkerState(t, s, j.ID) != state {
				t.Fatal("unknown original was changed or accepted without Root evidence")
			}
			var results int
			if s.DB.QueryRow(`SELECT count(*) FROM waf_country_results`).Scan(&results) != nil || results != 0 {
				t.Fatal("upgrade check created a substitute terminal")
			}
		})
	}
}

func TestWAFCountryUpgradeAllowsClosedOriginalButRefusesOrphansAndPartialSchema(t *testing.T) {
	for _, kind := range []string{"complete", "orphan", "wrong-key", "wrong-target", "partial-schema", "old-schema", "old-orphan"} {
		t.Run(kind, func(t *testing.T) {
			s, j, _, _ := countryWorkerFixture(t)
			if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error='pre-transfer source refusal' WHERE id=?`, j.ID); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "orphan":
				_, err = s.DB.Exec(`DELETE FROM waf_country_requests WHERE job_id=?`, j.ID)
			case "wrong-key":
				_, err = s.DB.Exec(`UPDATE waf_country_requests SET idempotency_key=? WHERE job_id=?`, ID(), j.ID)
			case "wrong-target":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET target_id='apache-waf' WHERE id=?`, j.ID)
			case "partial-schema":
				_, err = s.DB.Exec(`DROP TABLE waf_country_results`)
			case "old-schema", "old-orphan":
				_, err = s.DB.Exec(`DROP TABLE waf_country_results; DROP TABLE waf_country_requests`)
				if err == nil && kind == "old-schema" {
					_, err = s.DB.Exec(`DELETE FROM runtime_jobs WHERE id=?`, j.ID)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			reject := kind != "complete" && kind != "old-schema"
			if err := s.CheckWAFCountryUpgrade(context.Background()); (err != nil) != reject {
				t.Fatal("original Core upgrade state incorrectly classified", kind, err)
			}
		})
	}
}

func TestWAFCountryUpgradeOriginalWholeTerminalMustAgreeAndIsNeverRewritten(t *testing.T) {
	s, j, original, out := countryWorkerFixture(t)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.finishWAFCountryResult(context.Background(), j, raw, original.Actor, original.Selection, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckWAFCountryUpgrade(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed' WHERE id=?`, j.ID); err != nil {
		t.Fatal(err)
	}
	if s.CheckWAFCountryUpgrade(context.Background()) == nil {
		t.Fatal("late inconsistent terminal was accepted as drained")
	}
	var stored []byte
	if s.DB.QueryRow(`SELECT body FROM waf_country_results WHERE job_id=?`, j.ID).Scan(&stored) != nil || string(stored) != string(raw) || countryWorkerState(t, s, j.ID) != "failed" {
		t.Fatal("read-only admission repaired or relabelled original failure/result")
	}
}
