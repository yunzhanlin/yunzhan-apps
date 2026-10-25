package core

import (
	"errors"
	"time"
)

func validLogCleanupTime(value string) bool {
	at, e := time.Parse(time.RFC3339Nano, value)
	return e == nil && at.UTC().Format(time.RFC3339Nano) == value
}

func ValidLogCleanupInspection(v LogCleanupInspection, request, site string) bool {
	if !ValidID(request) || !ValidID(site) || v.RequestID != request || v.SiteID != site || !v.ReadOnly || v.Files == nil || len(v.Files) > 1002 {
		return false
	}
	if v.State == "not_recorded" {
		return v.RetentionDays == 0 && v.StartedAt == "" && v.PlanSHA256 == "" && len(v.Files) == 0 && v.Result == nil && v.Continuation == nil
	}
	if v.State != "completed" && v.State != "running" && v.State != "unknown" {
		return false
	}
	if v.RetentionDays < 1 || v.RetentionDays > 100 || !validLogCleanupTime(v.StartedAt) || !validLowerSHA256(v.PlanSHA256) {
		return false
	}
	if (v.State == "completed") != (v.Result != nil) {
		return false
	}
	if v.Result != nil {
		r := v.Result
		if r.Rotated < 0 || r.Rotated > 2 || r.Deleted < 0 || r.Deleted > 1000 || r.DeletedBytes < 0 || r.Files == nil || len(r.Files) != r.Deleted || r.Deleted == 0 && r.DeletedBytes != 0 {
			return false
		}
		seen := map[string]bool{}
		for _, name := range r.Files {
			if seen[name] || !ValidSiteLogArchiveName(site, name) {
				return false
			}
			seen[name] = true
		}
	}
	if v.Continuation != nil {
		c := v.Continuation
		if v.State == "completed" || c.RequestID != request || c.SiteID != site || c.PlanSHA256 != v.PlanSHA256 || !validLowerSHA256(c.EvidenceSHA256) || !validLogCleanupTime(c.VerifiedAt) {
			return false
		}
	}
	seen := map[string]bool{}
	expirationNames := map[string]bool{}
	rotations, expired := 0, 0
	for _, file := range v.Files {
		if seen[file.Name] || file.PlannedBytes < 0 || !validLogCleanupFileState(file.State) {
			return false
		}
		seen[file.Name] = true
		switch file.Role {
		case "rotation":
			rotations++
			if file.Name != "panel-"+site+".access.log" && file.Name != "panel-"+site+".error.log" || !validLogCleanupFileState(file.ArchiveState) {
				return false
			}
		case "expiration":
			expired++
			if !ValidSiteLogArchiveName(site, file.Name) || file.ArchiveState != "" {
				return false
			}
			expirationNames[file.Name] = true
		default:
			return false
		}
	}
	if v.Result != nil {
		if v.Result.Rotated > rotations || v.Result.Deleted > expired {
			return false
		}
		for _, name := range v.Result.Files {
			if !expirationNames[name] {
				return false
			}
		}
	}
	return rotations <= 2 && expired <= 1000
}

func validLogCleanupFileState(value string) bool {
	switch value {
	case "absent", "unverifiable", "different_inode", "original_inode_written", "original_inode_unchanged", "original_inode_owner_changed":
		return true
	}
	return false
}

var errLogCleanupInspection = errors.New("日志核实结果与任务身份、文件归属或状态不匹配")
