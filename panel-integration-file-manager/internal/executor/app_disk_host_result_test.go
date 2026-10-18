package executor

import (
	"reflect"
	"testing"

	"local/panel/internal/diskjob"
	"local/panel/internal/diskusage"
)

func TestDiskHostFailureReportDoesNotDuplicateScannerReason(t *testing.T) {
	for _, state := range []string{"failed", "canceled"} {
		code := "progress_or_authority_rejected"
		if state == "canceled" {
			code = "canceled"
		}
		result := diskjob.Result{State: state, ErrorCode: code, Report: &diskusage.ScanReport{State: "running", Complete: true, EntriesRead: 11904, IndexFlushed: false, Reasons: []string{code}}}
		markDiskHostFailureReport(&result)
		markDiskHostFailureReport(&result)
		if result.Report.Complete || result.Report.State != state || result.Report.EntriesRead != 11904 || result.Report.IndexFlushed || !reflect.DeepEqual(result.Report.Reasons, []string{code}) {
			t.Fatal("failure finalization duplicated a reason or changed incomplete counters/index state")
		}
	}
}

func TestDiskHostFailureReportPreservesAllOtherEvidence(t *testing.T) {
	result := diskjob.Result{Format: 1, State: "failed", ErrorCode: "index_unavailable_or_full", At: "original", RequestSHA: "original-request-digest", Report: &diskusage.ScanReport{SelectedPath: "/original", Complete: true, State: "running", EntriesRead: 8192, UniqueFiles: 8128, AllocatedBytes: 278528, IndexFlushed: false, Reasons: []string{"child_mount_excluded", "index_unavailable_or_capacity_reached"}}}
	expected := result
	report := *result.Report
	expected.Report = &report
	expected.Report.Complete = false
	expected.Report.State = "failed"
	expected.Report.Reasons = []string{"child_mount_excluded", "index_unavailable_or_capacity_reached", "index_unavailable_or_full"}
	markDiskHostFailureReport(&result)
	if !reflect.DeepEqual(result, expected) {
		t.Fatal("failure formatting changed identity/evidence or merged distinct reasons")
	}
}

func TestDiskHostFailureReportDoesNotManufactureMissingReport(t *testing.T) {
	markDiskHostFailureReport(nil)
	result := diskjob.Result{State: "failed", ErrorCode: "scan_or_authority_unavailable"}
	expected := result
	markDiskHostFailureReport(&result)
	if !reflect.DeepEqual(result, expected) || result.Report != nil {
		t.Fatal("missing report became invented counters or zero usage")
	}
}

func TestDiskHostFailureReportNeverAddsBlankReason(t *testing.T) {
	result := diskjob.Result{State: "failed", Report: &diskusage.ScanReport{Complete: true, State: "running", Reasons: []string{"scope_unavailable"}}}
	markDiskHostFailureReport(&result)
	if result.Report.Complete || result.Report.State != "failed" || !reflect.DeepEqual(result.Report.Reasons, []string{"scope_unavailable"}) {
		t.Fatal("blank code became a reason or a failure became complete")
	}
}

func TestDiskHostFailureReportHandlesNilReasonsWithoutResettingCounts(t *testing.T) {
	result := diskjob.Result{State: "failed", ErrorCode: "deadline_reached", Report: &diskusage.ScanReport{EntriesRead: 64}}
	markDiskHostFailureReport(&result)
	if result.Report.EntriesRead != 64 || !reflect.DeepEqual(result.Report.Reasons, []string{"deadline_reached"}) {
		t.Fatal("first failure reason was omitted or original metadata was reset")
	}
}

func TestDiskHostFailureReportDoesNotRewriteExistingReasons(t *testing.T) {
	reasons := []string{"progress_or_authority_rejected", "progress_or_authority_rejected"}
	result := diskjob.Result{State: "failed", ErrorCode: reasons[0], Report: &diskusage.ScanReport{Reasons: append([]string{}, reasons...)}}
	markDiskHostFailureReport(&result)
	if !reflect.DeepEqual(result.Report.Reasons, reasons) {
		t.Fatal("failure annotation rewrote existing evidence instead of avoiding a new duplicate")
	}
}
