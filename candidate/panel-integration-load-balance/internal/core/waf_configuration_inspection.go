package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

type WAFConfigurationDifference struct {
	Scope          string `json:"scope"`
	SiteID         string `json:"site_id"`
	ActualExists   bool   `json:"actual_exists"`
	ExpectedExists bool   `json:"expected_exists"`
	ActualSHA      string `json:"actual_sha256"`
	ExpectedSHA    string `json:"expected_sha256"`
	ActualMode     uint32 `json:"actual_mode"`
	ExpectedMode   uint32 `json:"expected_mode"`
	ActualBytes    int    `json:"actual_bytes"`
	ExpectedBytes  int    `json:"expected_bytes"`
}
type WAFConfigurationInspection struct {
	Format              int                          `json:"format"`
	ReadOnly            bool                         `json:"read_only"`
	InstalledVersion    string                       `json:"installed_version"`
	PolicyRevision      string                       `json:"policy_revision"`
	SemanticRecordSHA   string                       `json:"semantic_record_sha256"`
	FilesystemMatches   bool                         `json:"filesystem_matches"`
	EnforcementVerified bool                         `json:"enforcement_verified"`
	Differences         []WAFConfigurationDifference `json:"differences"`
}

func WAFInspectionVersionSupported(v string) bool {
	switch v {
	case "2.0.1", "2.1.0", "2.1.1", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.5.1", "2.5.2", "2.6.0":
		return true
	}
	return false
}
func DecodeWAFConfigurationInspection(raw []byte) (WAFConfigurationInspection, error) {
	var out WAFConfigurationInspection
	bad := errors.New("已安装 WAF 配置差异无法完整核对；未返回部分成功结果")
	top := []string{"format", "read_only", "installed_version", "policy_revision", "semantic_record_sha256", "filesystem_matches", "enforcement_verified", "differences"}
	if len(raw) > 2<<20 || !wafInventoryJSONShape(raw, top) {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Format != 1 || !out.ReadOnly || out.EnforcementVerified || !WAFInspectionVersionSupported(out.InstalledVersion) || out.Differences == nil || len(out.Differences) > 4110 || out.FilesystemMatches != (len(out.Differences) == 0) {
		return WAFConfigurationInspection{}, bad
	}
	revision, revisionErr := strconv.ParseInt(out.PolicyRevision, 10, 64)
	if revisionErr != nil || revision < 0 || strconv.FormatInt(revision, 10) != out.PolicyRevision {
		return WAFConfigurationInspection{}, bad
	}
	validSHA := func(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }
	if !validSHA(out.SemanticRecordSHA) {
		return WAFConfigurationInspection{}, bad
	}
	var shape struct {
		Rows []json.RawMessage `json:"differences"`
	}
	if json.Unmarshal(raw, &shape) != nil || len(shape.Rows) != len(out.Differences) {
		return WAFConfigurationInspection{}, bad
	}
	seen := map[string]bool{}
	total := 0
	for i, row := range out.Differences {
		if !wafInventoryJSONShape(shape.Rows[i], []string{"scope", "site_id", "actual_exists", "expected_exists", "actual_sha256", "expected_sha256", "actual_mode", "expected_mode", "actual_bytes", "expected_bytes"}) || !validSHA(row.ActualSHA) || !validSHA(row.ExpectedSHA) || row.ActualMode > 0777 || row.ExpectedMode > 0777 || row.ActualBytes < 0 || row.ExpectedBytes < 0 || row.ActualBytes > 8<<20 || row.ExpectedBytes > 8<<20 {
			return WAFConfigurationInspection{}, bad
		}
		scoped := row.Scope == "site" || row.Scope == "body-site"
		if scoped && !ValidID(row.SiteID) || !scoped && row.SiteID != "" {
			return WAFConfigurationInspection{}, bad
		}
		switch row.Scope {
		case "nginx-main", "http-rules", "server-rules", "native-log", "manifest", "site", "body-site":
		default:
			return WAFConfigurationInspection{}, bad
		}
		key := row.Scope + "/" + row.SiteID
		if seen[key] || !row.ActualExists && (row.ActualBytes != 0 || row.ActualMode != 0) || !row.ExpectedExists && (row.ExpectedBytes != 0 || row.ExpectedMode != 0) || row.ActualExists == row.ExpectedExists && row.ActualSHA == row.ExpectedSHA && row.ActualMode == row.ExpectedMode {
			return WAFConfigurationInspection{}, bad
		}
		seen[key] = true
		if !row.ActualExists && row.ActualSHA != Hash("") || !row.ExpectedExists && row.ExpectedSHA != Hash("") {
			return WAFConfigurationInspection{}, bad
		}
		total += row.ActualBytes + row.ExpectedBytes
		if total > 8<<20 {
			return WAFConfigurationInspection{}, bad
		}
	}
	return out, nil
}
