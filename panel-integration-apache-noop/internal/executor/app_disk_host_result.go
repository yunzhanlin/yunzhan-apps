package executor

import "local/panel/internal/diskjob"

// The scanner may already have recorded the worker's failure code. Preserve
// every original reason and counter, but do not add the same failure twice.
// This only finalizes a NEW worker result; stored receipts are never repaired.
func markDiskHostFailureReport(result *diskjob.Result) {
	if result == nil || result.Report == nil {
		return
	}
	result.Report.Complete = false
	result.Report.State = result.State
	if result.ErrorCode == "" {
		return
	}
	for _, reason := range result.Report.Reasons {
		if reason == result.ErrorCode {
			return
		}
	}
	result.Report.Reasons = append(result.Report.Reasons, result.ErrorCode)
}
