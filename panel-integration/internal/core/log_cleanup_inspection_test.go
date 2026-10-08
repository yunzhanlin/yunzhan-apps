package core

import "testing"

func TestLogCleanupInspectionRejectsForeignFilesUnknownStatesAndInconsistentResult(t *testing.T) {
	site, request := ID(), ID()
	base := LogCleanupInspection{RequestID: request, SiteID: site, State: "unknown", RetentionDays: 2, StartedAt: "2026-10-08T12:00:00Z", PlanSHA256: Hash("plan"), ReadOnly: true, Files: []LogCleanupFileInspection{{Name: "panel-" + site + ".access.log", Role: "rotation", State: "different_inode", ArchiveState: "original_inode_unchanged", PlannedBytes: 5}}}
	if !ValidLogCleanupInspection(base, request, site) {
		t.Fatal("valid inspection rejected")
	}
	for _, fault := range []string{"site", "request", "state", "nil_files", "retention", "time", "digest", "foreign_file", "role", "file_state", "unexpected_result", "completed_without_result", "foreign_continuation"} {
		t.Run(fault, func(t *testing.T) {
			v := base
			v.Files = append([]LogCleanupFileInspection{}, base.Files...)
			switch fault {
			case "site":
				v.SiteID = ID()
			case "request":
				v.RequestID = ID()
			case "state":
				v.State = "automatically_accepted"
			case "nil_files":
				v.Files = nil
			case "retention":
				v.RetentionDays = 101
			case "time":
				v.StartedAt = "yesterday"
			case "digest":
				v.PlanSHA256 = "bad"
			case "foreign_file":
				v.Files[0].Name = "panel-" + ID() + ".access.log"
			case "role":
				v.Files[0].Role = "delete_anything"
			case "file_state":
				v.Files[0].State = "accepted"
			case "unexpected_result":
				v.Result = &LogCleanupResult{Files: []string{}}
			case "completed_without_result":
				v.State = "completed"
			case "foreign_continuation":
				v.Continuation = &LogCleanupContinuation{RequestID: ID(), SiteID: site, PlanSHA256: v.PlanSHA256, VerifiedAt: v.StartedAt, EvidenceSHA256: Hash("evidence")}
			}
			if ValidLogCleanupInspection(v, request, site) {
				t.Fatal("ambiguous inspection accepted", fault)
			}
		})
	}
}
