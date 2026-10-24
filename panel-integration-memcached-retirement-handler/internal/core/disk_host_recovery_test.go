package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"local/panel/internal/diskjob"
)

func TestHostDiskRecoveryDeletedOwnerMetadataCloseDoesNotAdoptOrReplay(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "orphan-original", "admin", nil)
	op := accessUser(t, s, "orphan-current", "admin", nil)
	limited := accessUser(t, s, "orphan-limited", "admin", []string{"system-tools", "runtimes"})
	j, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	j, _, err = s.HostDiskDispatchBoundary(ctx, j.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM app_user_roles WHERE user_id=?", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM users WHERE id=?", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PrepareHostDiskRecovery(ctx, j.ID, limited.ID); err == nil {
		t.Fatal("limited user acquired orphan control")
	}
	_, request, err := s.PrepareHostDiskRecovery(ctx, j.ID, op.ID)
	if err != nil || request == nil || request.Request != j.Request || request.Operator.ActorID != op.ID {
		t.Fatal("original orphan identity adopted/replaced", request, err)
	}
	if err := s.ValidateHostDiskRecovery(ctx, *request); err != nil {
		t.Fatal("current full operator cannot reconcile deleted principal", err)
	}
	if err := s.ValidateHostDiskNative(ctx, j.Request); err == nil {
		t.Fatal("recovery revived deleted principal execution")
	}
	ack := diskjob.RecoveryAck{Format: 1, JobID: j.ID, RequestSHA: diskjob.RequestSHA(j.Request), State: "cancel_requested", SignalRequested: true}
	if got, err := s.FinishHostDiskRecovery(ctx, *request, ack); err != nil || got.State != "cancel_requested" {
		t.Fatal("signal released orphan slot", got.State, err)
	}
	c := diskjob.Closure{Format: 1, JobID: j.ID, RequestSHA: diskjob.RequestSHA(j.Request), OwnerID: u.ID, Kind: "admission_closed", State: "canceled", At: time.Now().UTC().Format(time.RFC3339Nano), ScopeEmpty: true, AdmissionSealed: true}
	ack.State = "canceled"
	ack.SignalRequested = false
	ack.Closure = &c
	for range 3 {
		got, err := s.FinishHostDiskRecovery(ctx, *request, ack)
		if err != nil || got.State != "canceled" || got.Request.ActorID != u.ID {
			t.Fatal(got.State, err)
		}
	}
	var count int
	if s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='disk.host.close' AND actor=? AND target=?", op.ID, j.ID).Scan(&count) != nil || count != 1 {
		t.Fatal("closure actor not current operator or audit duplicated", count)
	}
	if _, err := s.HostDiskForActor(ctx, j.ID, op.ID); err == nil {
		t.Fatal("maintenance operator acquired old private report/history")
	}
	if _, err := s.DB.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'disk.host.result',?,?,?)", u.ID, j.ID, c.RequestSHA, Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHostDiskUpgrade(ctx); err == nil {
		t.Fatal("conflicting completion evidence ignored")
	}
	// Owned SQLite fixture only; restore its injected conflict for later checks.
	if _, err := s.DB.Exec("DELETE FROM audit_logs WHERE action='disk.host.result' AND target=?", j.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHostDiskUpgrade(ctx); err != nil {
		t.Fatal("closed orphan still blocked upgrade", err)
	}
	if _, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), op.ID); err != nil {
		t.Fatal("verified admission seal did not release active slot", err)
	}
	bad := c
	bad.OwnerID = op.ID
	ack.Closure = &bad
	if _, err := s.FinishHostDiskRecovery(ctx, *request, ack); err == nil {
		t.Fatal("late closure changed original owner")
	}
}

func TestHostDiskRecoveryCurrentPermissionRecheckedAndSealCannotBeInvented(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "recovery-owner", "admin", nil)
	j, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Pure undispatched queue can be canceled without fabricating a Root job.
	got, request, err := s.PrepareHostDiskRecovery(ctx, j.ID, u.ID)
	if err != nil || request != nil || got.State != "canceled" || got.CancelState != "not_dispatched" {
		t.Fatal(got, request, err)
	}
	j, _, err = s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	_, request, err = s.PrepareHostDiskRecovery(ctx, j.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	c := diskjob.Closure{Format: 1, JobID: j.ID, RequestSHA: diskjob.RequestSHA(j.Request), OwnerID: u.ID, Kind: "admission_closed", State: "complete", At: time.Now().UTC().Format(time.RFC3339Nano), ScopeEmpty: true, AdmissionSealed: true}
	ack := diskjob.RecoveryAck{Format: 1, JobID: j.ID, RequestSHA: c.RequestSHA, State: c.State, Closure: &c}
	if _, err := s.FinishHostDiskRecovery(ctx, *request, ack); err == nil {
		t.Fatal("admission seal became invented successful scan")
	}
	c.State = "canceled"
	ack.State = "canceled"
	if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateHostDiskRecovery(ctx, *request); err == nil {
		t.Fatal("revoked operator still controlled Root recovery")
	}
	if _, err := s.FinishHostDiskRecovery(ctx, *request, ack); err == nil {
		t.Fatal("revoked operator committed terminal metadata")
	}
	if _, err := s.DB.Exec("UPDATE app_user_menus SET menu_ids='null',revision=3 WHERE user_id=?", u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateHostDiskRecovery(ctx, *request); err == nil {
		t.Fatal("stale operator revision restored recovery authority")
	}
	if _, _, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID); err != nil {
		t.Fatal("observation-only canceled original boundary refused", err)
	}
	var sha string
	if s.DB.QueryRow("SELECT dispatch_sha256 FROM disk_host_jobs WHERE id=?", j.ID).Scan(&sha) != nil || len(sha) != 64 || strings.Trim(sha, "0") == "" {
		t.Fatal("original committed dispatch binding lost")
	}
}
