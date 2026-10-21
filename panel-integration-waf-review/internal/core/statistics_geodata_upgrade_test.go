package core

import (
	"context"
	"strings"
	"testing"
)

func TestStatisticsGeoFailedUpgradeProofRequiresOriginalTwoSidedTerminalIdentity(t *testing.T) {
	for _, mutation := range []string{"original", "revoked", "deleted-actor", "missing-job", "wrong-kind", "wrong-target", "wrong-key", "changed-selection", "changed-error", "queued", "running", "succeeded", "needs_attention", "missing-queue", "duplicate-queue", "queue-result", "queue-actor", "missing-dispatch", "duplicate-dispatch", "dispatch-actor", "dispatch-digest", "orphan-audit", "wrong-root-id", "wrong-root-error", "empty-root-error", "root-success", "root-rollback", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "geo-upgrade-original", "admin", nil)
			in := statisticsGeoSelectionFixture()
			if _, err := s.QueueStatisticsGeo(in, strings.Repeat("a", 32), u.ID); err != nil {
				t.Fatal(err)
			}
			job, err := s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.statisticsGeoDispatchBoundary(t.Context(), job, true); err != nil {
				t.Fatal(err)
			}
			if err = s.FinishRuntime(job, "original synthetic download failure", nil); err != nil {
				t.Fatal(err)
			}
			out := StatisticsGeoOperation{JobID: job.ID, Selection: in, State: "failed", Error: "original synthetic download failure"}
			statement, args := "", []any{job.ID}
			switch mutation {
			case "revoked":
				statement, args = "UPDATE app_user_roles SET role='viewer' WHERE user_id=?", []any{u.ID}
			case "deleted-actor":
				statement, args = "DELETE FROM users WHERE id=?", []any{u.ID}
			case "missing-job":
				statement = "DELETE FROM runtime_jobs WHERE id=?"
			case "wrong-kind":
				statement = "UPDATE runtime_jobs SET kind='software_install' WHERE id=?"
			case "wrong-target":
				statement = "UPDATE runtime_jobs SET target_id='website-analytics' WHERE id=?"
			case "wrong-key":
				statement = "UPDATE runtime_jobs SET idempotency_key='' WHERE id=?"
			case "changed-selection":
				statement = "UPDATE runtime_jobs SET payload='{}' WHERE id=?"
			case "changed-error":
				statement = "UPDATE runtime_jobs SET error='different failure' WHERE id=?"
			case "queued", "running", "succeeded", "needs_attention":
				statement, args = "UPDATE runtime_jobs SET state=? WHERE id=?", []any{mutation, job.ID}
			case "missing-queue", "missing-dispatch":
				action := "statistics.geodata.queue"
				if mutation == "missing-dispatch" {
					action = "statistics.geodata.dispatch"
				}
				statement, args = "DELETE FROM audit_logs WHERE action=? AND target=?", []any{action, job.ID}
			case "duplicate-queue", "duplicate-dispatch":
				action := "statistics.geodata.queue"
				if mutation == "duplicate-dispatch" {
					action = "statistics.geodata.dispatch"
				}
				statement, args = "INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action=? AND target=?", []any{action, job.ID}
			case "queue-result":
				statement = "UPDATE audit_logs SET result='different' WHERE action='statistics.geodata.queue' AND target=?"
			case "queue-actor":
				statement = "UPDATE audit_logs SET actor='ffffffffffffffffffffffffffffffff' WHERE action='statistics.geodata.queue' AND target=?"
			case "dispatch-actor":
				statement = "UPDATE audit_logs SET actor='ffffffffffffffffffffffffffffffff' WHERE action='statistics.geodata.dispatch' AND target=?"
			case "dispatch-digest":
				statement = "UPDATE audit_logs SET result='different' WHERE action='statistics.geodata.dispatch' AND target=?"
			case "orphan-audit":
				statement, args = "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.queue',?,'queued',?)", []any{u.ID, ID(), Now()}
			case "wrong-root-id":
				out.JobID = ID()
			case "wrong-root-error":
				out.Error = "different root error"
			case "empty-root-error":
				out.Error = ""
			case "root-success":
				out.State = "succeeded"
			case "root-rollback":
				out.Selection.Action = "rollback"
			}
			if statement != "" {
				if _, err = s.DB.Exec(statement, args...); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mutation == "cancelled" {
				cancel()
			}
			before := geoRequestCounts(t, s)
			var changes, afterChanges int
			if err = s.DB.QueryRow("SELECT total_changes()").Scan(&changes); err != nil {
				t.Fatal(err)
			}
			err = s.ValidateStatisticsGeoFailedInstall(ctx, out)
			want := mutation == "original" || mutation == "revoked" || mutation == "deleted-actor"
			if (err == nil) != want {
				t.Fatal("terminal proof boundary", mutation, err)
			}
			if e := s.DB.QueryRow("SELECT total_changes()").Scan(&afterChanges); e != nil || changes != afterChanges || before != geoRequestCounts(t, s) {
				t.Fatal("proof mutated original data", e)
			}
		})
	}
}
