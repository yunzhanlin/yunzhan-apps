package diskjob

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/diskusage"
)

func receiptFixture() (Request, Dispatch, Started, Result) {
	in := Request{Format: 1, JobID: strings.Repeat("5", 32), ActorID: strings.Repeat("6", 32), AccessRevision: "1", Selection: selectionFixture()}
	d := Dispatch{1, in.JobID, in.ActorID, RequestSHA(in), strings.Repeat("7", 64)}
	unit, _ := UnitName(in.JobID, false)
	s := Started{1, in.JobID, d.RequestSHA, d.ExecutorSHA, "1234", "987654", "2026-10-15T00:00:00Z", Policy{Host: Host{in.Selection.BootID, in.Selection.NamespaceID}, Cgroup: "/system.slice/" + unit, Threads: 6, Capabilities: "CAP_DAC_READ_SEARCH", NoNewPrivileges: true, CPUQuota: "20000 100000", MemoryMax: "536870912", MemoryHigh: "402653184", MemorySwapMax: "0", TasksMax: "32", IOWeight: "default 10", FileDescriptorsMax: 2048, FileBytesMax: 1 << 30}}
	r := Result{Format: 1, Request: in, RequestSHA: d.RequestSHA, Started: s, State: "complete", At: "2026-10-15T00:00:02Z", Capacity: diskusage.Capacity{State: "unavailable", InodeState: "unavailable", MayOverlap: true},
		Report: &diskusage.ScanReport{Format: 1, MountID: in.Selection.MountID, BindingSHA: in.Selection.MountSHA, SelectedPath: "/srv/example", State: "complete", StartedAt: "2026-10-15T00:00:00.1Z", FinishedAt: "2026-10-15T00:00:01.9Z", Complete: true, IndexFlushed: true, Accounting: "st_blocks_512_per_inode_not_exclusive_extents", DirectoryAttribution: "first_observed_inode_within_this_scan", Budget: diskusage.DefaultScanBudget(), Reasons: []string{}, TopFiles: []diskusage.UsageRow{}, TopDirectories: []diskusage.UsageRow{}}}
	return in, d, s, r
}

func TestHostReceiptCanonicalNestedJSONAndExactBinding(t *testing.T) {
	in, d, s, r := receiptFixture()
	raw, _ := json.Marshal(r)
	if _, err := DecodeResult(raw, s, d, in); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{
		{`"format":1`, `"format":1,"format":1`},
		{`"report":{`, `"report":{"unknown":true,`},
		{`"enumeration_complete":true`, `"enumeration_complete":true,"enumeration_complete":true`},
		{`"snapshot_consistent":false`, `"snapshot_consistent":null`},
		{`"snapshot_consistent":false,`, ``},
		{`"threads_checked":6`, `"Threads_Checked":6`},
		{`"metadata_entries_read":"0"`, `"metadata_entries_read":0`},
		{`"metadata_entries_read":"0"`, `"metadata_entries_read":"00"`},
		{`"report":{`, `"Report":{`},
	} {
		bad := strings.Replace(string(raw), change[0], change[1], 1)
		if bad == string(raw) {
			t.Fatal("fixture mutation did not apply", change)
		}
		if _, err := DecodeResult([]byte(bad), s, d, in); err == nil {
			t.Fatal("ambiguous nested receipt accepted", change)
		}
	}
	if _, err := DecodeResult(append(raw, []byte("{}")...), s, d, in); err == nil {
		t.Fatal("trailing result accepted")
	}
	other := in
	other.Selection.InstallationID = strings.Repeat("8", 32)
	if _, err := DecodeResult(raw, s, d, other); err == nil {
		t.Fatal("result adopted by another app instance")
	}
	other = in
	other.ActorID = strings.Repeat("8", 32)
	if _, err := DecodeResult(raw, s, d, other); err == nil {
		t.Fatal("result adopted by another actor")
	}
}

func TestHostReceiptRejectsFalseCompleteAndInvalidCapacity(t *testing.T) {
	for _, mutate := range []func(*Result){
		func(r *Result) { r.Report.State = "partial" },
		func(r *Result) { r.Report.IndexFlushed = false },
		func(r *Result) { r.Report.Reasons = []string{"entry_budget_reached"} },
		func(r *Result) { r.Report.UnknownEntries = 1 },
		func(r *Result) { r.Report.OwnWorkerDirectories = 1 },
		func(r *Result) { r.Report.SnapshotConsistent = true },
		func(r *Result) { r.Report.ExclusivePhysicalBytes = true },
		func(r *Result) { r.Report.Budget.Entries++ },
		func(r *Result) { r.Report.TopFiles = nil },
		func(r *Result) { r.Capacity.MayOverlap = false },
		func(r *Result) { r.Capacity.TotalBytes = new(string) },
		func(r *Result) { r.ErrorCode = "untrusted /private/path" },
		func(r *Result) { r.At = "2026-10-14T23:59:59Z" },
	} {
		in, d, s, r := receiptFixture()
		mutate(&r)
		if ValidateResult(r, s, d, in) == nil {
			t.Fatal("false complete, unsafe policy or capacity accepted")
		}
	}
	in, d, s, r := receiptFixture()
	r.State = "failed"
	r.Report = nil
	r.ErrorCode = "scan_or_authority_unavailable"
	if ValidateResult(r, s, d, in) != nil {
		t.Fatal("unavailable original scan forced into fake zero/complete")
	}
	r.State = "canceled"
	r.ErrorCode = "canceled"
	if ValidateResult(r, s, d, in) != nil {
		t.Fatal("typed canceled pre-enumeration receipt refused")
	}
}

func TestHostReceiptSavedResultAndNativeExitAreSeparate(t *testing.T) {
	in, _, s, r := receiptFixture()
	o := Observation{Format: 1, Request: in, State: "settling", Process: "alive", Scope: "busy", Started: &s, Result: &r, ResultSHA: ResultSHA(r)}
	if ValidateObservation(o, in) != nil {
		t.Fatal("saved-but-running result not observable")
	}
	o.TerminalVerified = true
	o.State = "complete"
	if ValidateObservation(o, in) == nil {
		t.Fatal("saved result completed a still-running worker")
	}
	for _, process := range []string{"unknown", "alive", "gone"} {
		for _, scope := range []string{"unknown", "busy", "empty"} {
			for _, free := range []bool{false, true} {
				o.Process, o.Scope, o.RunLeaseFree = process, scope, free
				err := ValidateObservation(o, in)
				if (err == nil) != (process == "gone" && scope == "empty" && free) {
					t.Fatal("terminal conjunction weakened", process, scope, free, err)
				}
			}
		}
	}
	o.ResultSHA = strings.Repeat("1", 64)
	if ValidateObservation(o, in) == nil {
		t.Fatal("changed original result digest accepted")
	}
}

func TestHostReceiptProgressIsNeverTerminalAndLongPathsFitBound(t *testing.T) {
	in, d, s, r := receiptFixture()
	p := Progress{Format: 1, RequestSHA: d.RequestSHA, Started: s, At: "2026-10-15T00:00:01Z", Report: *r.Report}
	p.Report.State = "running"
	p.Report.Complete = false
	p.Report.FinishedAt = ""
	raw, _ := json.Marshal(p)
	if _, err := DecodeProgress(raw, s, d, in); err != nil {
		t.Fatal(err)
	}
	p.Report.Complete = true
	raw, _ = json.Marshal(p)
	if _, err := DecodeProgress(raw, s, d, in); err == nil {
		t.Fatal("progress became complete before terminal receipt")
	}
	for range 100 {
		row := diskusage.UsageRow{Path: "/" + strings.Repeat("&", 511), Actionable: true, LogicalBytes: 9007199254740993}
		r.Report.TopFiles = append(r.Report.TopFiles, row)
		r.Report.TopDirectories = append(r.Report.TopDirectories, row)
	}
	raw, _ = json.Marshal(r)
	if len(raw) <= 131072 || len(raw) > ReceiptBytesMax {
		t.Fatal("fixture misses escaped long-path bound", len(raw))
	}
	got, err := DecodeResult(raw, s, d, in)
	if err != nil || got.Report.TopFiles[0].LogicalBytes != 9007199254740993 {
		t.Fatal("long paths or safe JSON integers lost", err)
	}
}
