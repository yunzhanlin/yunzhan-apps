package core

import (
	"context"
	"encoding/json"
	"testing"

	"local/panel/internal/runtimecatalog"
)

func TestApacheRuntimeQueueBindsActorSelectionAndOriginalRevision(t *testing.T) {
	s := testStore(t)
	actor := accessUser(t, s, "apache-full", "", nil)
	other := accessUser(t, s, "apache-other", "", nil)
	fixed, _ := runtimecatalog.Find(runtimecatalog.ApacheCurrentID)
	if err := s.RecordObservedInstallation(fixed, "amd64"); err != nil {
		t.Fatal(err)
	}
	in := ApacheRuntimeSelection{fixed.ID, ID()}
	key := ID()
	id, err := s.QueueApacheRuntime(context.Background(), in, key, actor.ID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.QueueApacheRuntime(context.Background(), in, key, actor.ID)
	if err != nil || again != id {
		t.Fatal("same request was not attached", err)
	}
	changed := in
	changed.EngineJobID = ID()
	if _, err := s.QueueApacheRuntime(context.Background(), changed, key, actor.ID); err == nil {
		t.Fatal("changed engine reused original request")
	}
	if _, err := s.QueueApacheRuntime(context.Background(), in, key, other.ID); err == nil {
		t.Fatal("other administrator adopted original request")
	}
	job, err := s.NextRuntimeJob()
	if err != nil || job.ID != id {
		t.Fatal("ordinary runtime queue did not select switch", err)
	}
	request, err := s.apacheRuntimeDispatch(context.Background(), job)
	if err != nil || request.ActorID != actor.ID || request.ApacheRuntimeSelection != in {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO app_user_menus VALUES(?, ?, 2)`, actor.ID, func() string {
		all := []string{}
		for _, menu := range MenuPermissionCatalog() {
			all = append(all, menu.ID)
		}
		raw, _ := json.Marshal(all)
		return string(raw)
	}()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.apacheRuntimeDispatch(context.Background(), job); err == nil {
		t.Fatal("changed permission revision retained queued authority")
	}
	if _, err := s.QueueApacheRuntime(context.Background(), in, key, actor.ID); err == nil {
		t.Fatal("old request silently adopted new revision")
	}
	if err := s.FinishRuntime(job, "fixture stopped before dispatch", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryRuntime(id, actor.Username); err == nil {
		t.Fatal("generic retry could re-execute an old switch")
	}
}

func TestApacheRuntimeQueueRejectsLimitedActorsMissingRuntimeAndHistoricalTarget(t *testing.T) {
	s := testStore(t)
	full := accessUser(t, s, "apache-full", "", nil)
	limited := accessUser(t, s, "apache-limited", "admin", []string{"runtimes"})
	in := ApacheRuntimeSelection{ReleaseID: runtimecatalog.ApacheCurrentID}
	if _, err := s.QueueApacheRuntime(context.Background(), in, ID(), full.ID); err == nil {
		t.Fatal("missing runtime admitted")
	}
	fixed, _ := runtimecatalog.Find(in.ReleaseID)
	if err := s.RecordObservedInstallation(fixed, "amd64"); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{limited.ID, ID(), "admin"} {
		if _, err := s.QueueApacheRuntime(context.Background(), in, ID(), actor); err == nil {
			t.Fatal("limited/missing actor admitted")
		}
	}
	old := in
	old.ReleaseID = runtimecatalog.ApacheLegacyID
	if _, err := s.QueueApacheRuntime(context.Background(), old, ID(), full.ID); err == nil {
		t.Fatal("new action could select affected legacy runtime")
	}
	if _, err := s.QueueApacheRuntime(context.Background(), in, "arbitrary-request", full.ID); err == nil {
		t.Fatal("malformed request ID admitted")
	}
}

func TestApacheRuntimeCoreColdRecoveryDoesNotReplayOrOverwriteOriginalTerminalResult(t *testing.T) {
	s := testStore(t)
	actor := accessUser(t, s, "apache-cold", "", nil)
	fixed, _ := runtimecatalog.Find(runtimecatalog.ApacheCurrentID)
	if err := s.RecordObservedInstallation(fixed, "amd64"); err != nil {
		t.Fatal(err)
	}
	id, err := s.QueueApacheRuntime(context.Background(), ApacheRuntimeSelection{ReleaseID: fixed.ID}, ID(), actor.ID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.NextRuntimeJob()
	if err != nil || original.ID != id {
		t.Fatal(err)
	}
	if err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	current, err := s.Job(id)
	if err != nil || current.State != "needs_attention" || !current.RetryBlocked || current.Payload != original.Payload {
		t.Fatal("cold recovery requeued or changed original switch", current, err)
	}
	if _, err := s.NextRuntimeJob(); err == nil {
		t.Fatal("interrupted original switch became dispatchable")
	}
	if err := s.FinishRuntime(original, "original safely restored", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRuntime(original, "", nil); err != nil {
		t.Fatal(err)
	}
	current, err = s.Job(id)
	if err != nil || current.State != "failed" || current.Error != "original safely restored" {
		t.Fatal("late observer overwrote original terminal result", current, err)
	}
}
