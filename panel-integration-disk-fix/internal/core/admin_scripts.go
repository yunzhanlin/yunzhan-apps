package core

import (
	"encoding/json"
	"path"
	"strings"
)

type AdminScriptRequest struct {
	JobID          string `json:"job_id"`
	Script         string `json:"script"`
	ScriptSHA256   string `json:"script_sha256"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	SiteID         string `json:"site_id,omitempty"`
	PHPVersionID   string `json:"php_version_id,omitempty"`
}

// Preserve Shell receipt compatibility while binding PHP receipts to a site and
// the exact runtime selected when this run started.
func AdminScriptHash(script, siteID, releaseID string) string {
	if siteID == "" && releaseID == "" {
		return Hash(script)
	}
	b, _ := json.Marshal([]string{script, siteID, releaseID})
	return Hash(string(b))
}

func ValidSitePHPScriptPath(value string) bool {
	return len(value) > 0 && len(value) <= 1024 && !strings.ContainsAny(value, "\\\x00\r\n") &&
		!path.IsAbs(value) && path.Clean(value) == value && value != ".." &&
		!strings.HasPrefix(value, "../") && !strings.HasPrefix(value, "-") && strings.HasSuffix(value, ".php")
}

type AdminScriptResult struct {
	State      string `json:"state"`
	Output     string `json:"output"`
	Truncated  bool   `json:"truncated"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
}
