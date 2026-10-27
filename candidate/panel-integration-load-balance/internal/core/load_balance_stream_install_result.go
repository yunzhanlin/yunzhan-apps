package core

import (
	"bytes"
	"encoding/json"
	"local/panel/internal/loadbalancestream"
)

func DecodeLoadBalanceStreamInstallResult(raw []byte, job string) (LoadBalanceStreamInstallResult, error) {
	var v LoadBalanceStreamInstallResult
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &v) != nil || ValidateLoadBalanceStreamInstallResult(v, job) != nil {
		return v, errLoadBalanceStreamInstallAuthority
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return LoadBalanceStreamInstallResult{}, errLoadBalanceStreamInstallAuthority
	}
	return v, nil
}

// A known Root error envelope can terminate original read-only observation as
// UNKNOWN, never as success. Unavailable transport or arbitrary HTTP error
// text is not silently converted into evidence about the original job.
func decodeLoadBalanceStreamInstallError(raw []byte, job string) (LoadBalanceStreamInstallResult, bool) {
	var v struct {
		LoadBalanceStreamInstallResult
		Error string `json:"error"`
	}
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &v) != nil || len(v.Error) == 0 || len(v.Error) > 1024 || v.State != "unknown" || ValidateLoadBalanceStreamInstallResult(v.LoadBalanceStreamInstallResult, job) != nil {
		return LoadBalanceStreamInstallResult{}, false
	}
	canonical, err := json.Marshal(v)
	return v.LoadBalanceStreamInstallResult, err == nil && bytes.Equal(raw, canonical)
}

// A Root observation, not an input capability or a generic module health flag.
// A successful empty installation does not claim provisioned traffic service.
type LoadBalanceStreamInstallResult struct {
	Format                int    `json:"format"`
	JobID                 string `json:"job_id"`
	Version               string `json:"version"`
	State                 string `json:"state"`
	InstallationID        string `json:"installation_id,omitempty"`
	SeedSHA256            string `json:"seed_sha256,omitempty"`
	FinalEventSHA256      string `json:"final_event_sha256,omitempty"`
	PublishedModuleSHA256 string `json:"published_module_sha256,omitempty"`
	AccountReceiptSHA256  string `json:"account_receipt_sha256,omitempty"`
	RuntimeProvisioned    bool   `json:"runtime_provisioned"`
}

func ValidateLoadBalanceStreamInstallResult(v LoadBalanceStreamInstallResult, job string) error {
	if v.Format != 1 || !ValidID(job) || v.JobID != job || v.Version != loadbalancestream.AppVersion || v.RuntimeProvisioned {
		return errLoadBalanceStreamInstallAuthority
	}
	if v.State != "committed" && v.State != "unknown" && v.State != "not-found" && v.State != "running" {
		return errLoadBalanceStreamInstallAuthority
	}
	if v.State == "committed" {
		if !ValidID(v.InstallationID) {
			return errLoadBalanceStreamInstallAuthority
		}
		for _, h := range []string{v.SeedSHA256, v.FinalEventSHA256, v.PublishedModuleSHA256, v.AccountReceiptSHA256} {
			if !streamControlDigest(h) {
				return errLoadBalanceStreamInstallAuthority
			}
		}
	} else if v.InstallationID != "" || v.SeedSHA256 != "" || v.FinalEventSHA256 != "" || v.PublishedModuleSHA256 != "" || v.AccountReceiptSHA256 != "" {
		return errLoadBalanceStreamInstallAuthority
	}
	return nil
}
