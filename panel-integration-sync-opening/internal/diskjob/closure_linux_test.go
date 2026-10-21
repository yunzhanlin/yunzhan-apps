//go:build linux

package diskjob

import (
	"encoding/json"
	"os"
	"testing"
)

func TestHostNativeClosureLaunchAndRunLeasesExcludeLateAdmission(t *testing.T) {
	tree := nativeJournalFixture(t)
	in, _, _, _ := receiptFixture()
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	launch, err := j.LaunchLease()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.SealClosure(in); err == nil {
		t.Fatal("sealed while original launcher still held admission")
	}
	launch.Close()
	run, err := j.Lease()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.SealClosure(in); err == nil {
		t.Fatal("sealed while original worker held run lease")
	}
	run.Close()
	c, err := j.SealClosure(in)
	if err != nil || c.Kind != "admission_closed" || c.State != "canceled" || c.Started != nil {
		t.Fatal("admission closure became invented scan receipt", c, err)
	}
	if !j.AdmissionBlocked() {
		t.Fatal("late worker admission remained open")
	}
	if _, err := j.Closure(in); err != nil {
		t.Fatal("retained closed admission cannot be revalidated", err)
	}
	if err := tree.checkJobs(); err != nil {
		t.Fatal("verified closed admission blocked drain", err)
	}
	same, replay, err := publishRootRequest(tree, in)
	if same != nil {
		defer same.Close()
	}
	if err != nil || !replay {
		t.Fatal("closed original request was republished", replay, err)
	}
}

func TestHostNativeClosureInterruptedZeroReportRetainedNotPromoted(t *testing.T) {
	tree := nativeJournalFixture(t)
	in, d, s, _ := receiptFixture()
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for name, value := range map[string]any{"dispatch.json": d, "started.json": s} {
		raw, _ := json.Marshal(value)
		if err := j.WriteImmutable(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.root.WriteFile("result.json", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.root.WriteFile("progress.pending", []byte("interrupted original progress"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Observe(in); err == nil {
		t.Fatal("ordinary observer accepted zero report/pending progress")
	}
	c, err := j.SealClosure(in)
	if err != nil || c.Kind != "interrupted" || c.State != "failed" || c.ResultSHA != hashBytes(nil) {
		t.Fatal("empty report treated as success/zero filesystem", c, err)
	}
	if _, err := j.Read("result.json"); err == nil {
		t.Fatal("recovery weakened ordinary receipt reader")
	}
	if info, err := j.root.Lstat("result.json"); err != nil || info.Size() != 0 {
		t.Fatal("recovery altered original zero report", info, err)
	}
	if _, err := j.root.Lstat("progress.pending"); err != nil {
		t.Fatal("recovery deleted original interrupted progress")
	}
	if err := tree.checkJobs(); err != nil {
		t.Fatal("explicit failed closure could not drain", err)
	}
	if err := j.root.WriteFile("result.json", []byte("changed retained evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Closure(in); err == nil {
		t.Fatal("closure ignored changed original report bytes")
	}
}

func TestHostNativeClosureSuccessfulSummaryAndUnsafeEvidenceRemainDistinct(t *testing.T) {
	tree := nativeJournalFixture(t)
	in, d, s, r := receiptFixture()
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for name, value := range map[string]any{"dispatch.json": d, "started.json": s, "result.json": r} {
		raw, _ := json.Marshal(value)
		if err := j.WriteImmutable(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	c, err := j.SealClosure(in)
	if err != nil || c.Kind != "result_summary" || c.State != "complete" || c.ResultSHA != ResultSHA(r) {
		t.Fatal("genuine original result summary lost", c, err)
	}
	if _, err := j.Closure(in); err != nil {
		t.Fatal(err)
	}
	if err := j.root.Chmod("closure.json", 0644); err != nil {
		t.Fatal(err)
	}
	if !j.AdmissionBlocked() {
		t.Fatal("unsafe seal reopened worker admission")
	}
	if _, err := j.Closure(in); err == nil {
		t.Fatal("unsafe closure accepted")
	}
	if info, err := os.Lstat(tree.name + "/" + in.JobID + "/closure.json"); err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("observer repaired original unsafe evidence", info, err)
	}
}
