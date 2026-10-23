package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/diskjob"
)

func hostSelectionFixture() diskjob.Selection {
	return diskjob.Selection{BootID: "00000000-0000-4000-8000-000000000001", NamespaceID: "4:4026531841", MountID: "37", MountSHA: strings.Repeat("1", 64), Directory: "", AppVersion: diskjob.HostAppVersion, InstallationID: strings.Repeat("2", 32), AppSHA: strings.Repeat("3", 64)}
}

func TestHostDiskQueueActorIsolationAndSingleDispatch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "host-owner", "admin", nil)
	other := accessUser(t, s, "host-other", "admin", nil)
	key := ID()
	in := hostSelectionFixture()
	j, replayed, err := s.QueueHostDisk(ctx, in, key, u.ID)
	if err != nil || replayed || j.State != "queued" || j.Request.ActorID != u.ID || j.Request.AccessRevision != "1" {
		t.Fatal(j, replayed, err)
	}
	prior, replayed, err := s.QueueHostDisk(ctx, in, key, u.ID)
	if err != nil || !replayed || prior.ID != j.ID {
		t.Fatal("original queue recreated", prior, replayed, err)
	}
	if _, _, err := s.QueueHostDisk(ctx, in, key, other.ID); err == nil {
		t.Fatal("another administrator adopted original idempotency key")
	}
	if _, err := s.HostDiskForActor(ctx, j.ID, other.ID); err == nil {
		t.Fatal("another administrator read private host request")
	}
	if _, _, err := s.QueueHostDisk(ctx, in, ID(), other.ID); err == nil {
		t.Fatal("parallel host job allowed")
	}
	dispatch, observeOnly, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID)
	if err != nil || observeOnly || dispatch.State != "dispatching" || !diskjob.ValidSHA(dispatch.dispatchSHA) {
		t.Fatal(dispatch, observeOnly, err)
	}
	if err := s.ValidateHostDiskNative(ctx, dispatch.Request); err != nil {
		t.Fatal("original current private native intent refused", err)
	}
	for range 3 {
		same, only, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID)
		if err != nil || !only || same.dispatchSHA != dispatch.dispatchSHA {
			t.Fatal("crash/lost reply/restart redispatched", same, only, err)
		}
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='disk.host.dispatch' AND target=?", j.ID).Scan(&count)
	if count != 1 {
		t.Fatal("dispatch intent not unique")
	}
	canceled, err := s.RequestHostDiskCancel(ctx, j.ID, u.ID)
	if err != nil || canceled.State != "cancel_requested" || canceled.CancelState != "requested" {
		t.Fatal("native cancellation intent became terminal", canceled, err)
	}
	if err := s.ValidateHostDiskNative(ctx, dispatch.Request); err != ErrHostDiskCancelRequested {
		t.Fatal("private native worker ignored durable cancellation", err)
	}
	if _, _, err := s.QueueHostDisk(ctx, in, ID(), u.ID); err == nil {
		t.Fatal("requested/uncertain native cancellation released active slot")
	}
}

func TestHostDiskFullAdministratorRecheckedAndRevisionNotReplayed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := hostSelectionFixture()
	for _, f := range []struct {
		name, role string
		menus      []string
	}{{"limited-host", "admin", []string{"system-tools", "runtimes"}}, {"operator-host", "operator", nil}, {"viewer-host", "viewer", nil}} {
		u := accessUser(t, s, f.name, f.role, f.menus)
		if _, _, err := s.QueueHostDisk(ctx, in, ID(), u.ID); err == nil {
			t.Fatal("role/menu grant expanded to full-host authority", f)
		}
	}
	u := accessUser(t, s, "full-host", "admin", nil)
	j, _, err := s.QueueHostDisk(ctx, in, ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[\"system-tools\",\"runtimes\"]',2)", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID); err == nil {
		t.Fatal("revoked menu authority dispatched original root job")
	}
	if _, err := s.HostDiskForActor(ctx, j.ID, u.ID); err == nil {
		t.Fatal("limited administrator read full-host history")
	}
	if _, err := s.RequestHostDiskCancel(ctx, j.ID, u.ID); err == nil {
		t.Fatal("limited administrator changed privileged task")
	}
	if _, err := s.DB.Exec("UPDATE app_user_menus SET menu_ids='null',revision=3 WHERE user_id=?", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostDiskForActor(ctx, j.ID, u.ID); err != nil {
		t.Fatal("restored full owner cannot observe original request", err)
	}
	if _, _, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID); err == nil {
		t.Fatal("stale original authorization revision redispatched after restoration")
	}
	var state string
	s.DB.QueryRow("SELECT state FROM disk_host_jobs WHERE id=?", j.ID).Scan(&state)
	if state != "queued" {
		t.Fatal("denied dispatch mutated original task")
	}
	if _, err := s.DB.Exec("DELETE FROM app_user_roles WHERE user_id=?", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM app_user_menus WHERE user_id=?", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM users WHERE id=?", u.ID); err != nil {
		t.Fatal("history incorrectly blocks account deletion", err)
	}
	if _, err := s.HostDiskForActor(ctx, j.ID, u.ID); err == nil {
		t.Fatal("deleted actor expanded to default admin")
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM disk_host_jobs WHERE id=?", j.ID).Scan(&count)
	if count != 1 {
		t.Fatal("account deletion lost original job evidence")
	}
}

func TestHostDiskQueuedCancellationNoDispatchAndCorruptionFailClosed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "host-cancel-owner", "admin", nil)
	in := hostSelectionFixture()
	j, _, err := s.QueueHostDisk(ctx, in, ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	end, err := s.RequestHostDiskCancel(ctx, j.ID, u.ID)
	if err != nil || end.State != "canceled" || end.CancelState != "not_dispatched" || end.dispatchSHA != "" {
		t.Fatal(end, err)
	}
	_, only, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID)
	if err != nil || !only {
		t.Fatal("canceled queued task became native dispatch", only, err)
	}
	next, _, err := s.QueueHostDisk(ctx, in, ID(), u.ID)
	if err != nil {
		t.Fatal("verified undispatched cancellation did not release slot", err)
	}
	r := next.Request
	r.ActorID = ID()
	raw, _ := json.Marshal(r)
	if _, err := s.DB.Exec("UPDATE disk_host_jobs SET request=? WHERE id=?", string(raw), next.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostDiskForActor(ctx, next.ID, u.ID); err == nil {
		t.Fatal("corrupt actor binding read as private owner")
	}
	if _, _, err := s.HostDiskDispatchBoundary(ctx, next.ID, u.ID); err == nil {
		t.Fatal("corrupt binding dispatched")
	}
}
