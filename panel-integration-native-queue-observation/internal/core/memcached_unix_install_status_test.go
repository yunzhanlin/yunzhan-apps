package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMemcachedUnixInstallStatusOriginalReplayNeverFallsBackToLegacyObserver(t *testing.T) {
	s, _, op, item := memcachedUnixStoreFixture(t)
	prior := registryInstallReplay{op.JobID, item.Provider, op.ProjectID, item.Target}
	want := "/v1/docker/memcached-unix/installs/" + op.JobID
	if p, err := s.registryComposeReplayJobPath(context.Background(), prior); err != nil || p != want {
		t.Fatal("original Unix install used a mutating legacy observer", p, err)
	}
	if registryComposeInstallJobPath("memcached", "1.6.45-compat2", op.JobID) != "/v1/docker/jobs/"+op.JobID || registryComposeInstallJobPath("mongodb", item.Version, op.JobID) != "/v1/docker/jobs/"+op.JobID {
		t.Fatal("new independent route widened old application ABI")
	}
	if _, err := s.DB.Exec(`DELETE FROM app_registry_install_requests WHERE job_id=?`, op.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.registryComposeReplayJobPath(context.Background(), prior); err == nil {
		t.Fatal("missing original binding caused legacy observer fallback")
	}
}

func TestMemcachedUnixInstallStatusSeparatesHistoricalCommitFromLiveHealth(t *testing.T) {
	chain := memcachedUnixInstallChain(t, "")
	for _, record := range chain {
		out, err := MemcachedUnixInstallResult(record)
		if err != nil || out.JobID != record.Operation.JobID || out.ProjectID != record.Operation.ProjectID || out.Kind != "compose" {
			t.Fatal("original exact job projection", record.Phase, err)
		}
		want := "running"
		if record.Phase == "prepared" {
			want = "queued"
		}
		if record.Phase == "committed" {
			want = "succeeded"
			if out.ContainerID != record.ContainerID || !strings.Contains(out.Message, "另行实时检查") {
				t.Fatal("historical commit became current health")
			}
		} else if out.ContainerID != "" {
			t.Fatal("partial identity leaked as committed container")
		}
		if out.State != want {
			t.Fatal(record.Phase, out.State)
		}
		raw, _ := json.Marshal(out)
		for _, private := range []string{record.Operation.ActorID, record.Operation.Compose, record.CatalogSHA256, record.SubmissionSHA256, record.Binding.ManifestSHA256} {
			if private != "" && strings.Contains(string(raw), private) {
				t.Fatal("private original authority returned as status", private)
			}
		}
	}
	first := chain[0]
	for _, state := range []string{"refused", "needs-attention"} {
		row := first
		row.Sequence, row.Phase, row.Fault = 1, state, "authority-unavailable"
		out, err := MemcachedUnixInstallResult(row)
		if err != nil || out.Error == "" || out.State == "succeeded" {
			t.Fatal("uncertain/refused original became success", err)
		}
	}
	first.Phase = "forged-success"
	if _, err := MemcachedUnixInstallResult(first); err == nil {
		t.Fatal("unvalidated phase projected")
	}
}
