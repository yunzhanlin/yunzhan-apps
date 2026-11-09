package core

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

type WAFCountryCacheEntry struct {
	Dataset              string   `json:"dataset"`
	DataManifestSHA      string   `json:"data_manifest_sha256"`
	Countries            []string `json:"countries"`
	Release              string   `json:"release"`
	Revision             int      `json:"revision"`
	OriginalJobID        string   `json:"original_job_id"`
	PlanSHA              string   `json:"plan_sha256"`
	PreparedAt           string   `json:"prepared_at"`
	Bytes                int64    `json:"bytes"`
	Networks             int      `json:"networks"`
	Published            bool     `json:"published"`
	Reused               bool     `json:"reused"`
	ActivatedNginxPolicy bool     `json:"activated_nginx_policy"`
}

// Observation of ONE original data task, never evidence of enabled protection.
// No install/configure/source URL, command or caller verification flag exists.
type WAFCountryDataOperation struct {
	Format                 int                     `json:"format"`
	JobID                  string                  `json:"job_id"`
	ActorID                string                  `json:"actor_id"`
	Selection              WAFCountryDataSelection `json:"selection"`
	PayloadSHA             string                  `json:"payload_sha256"`
	RequestSHA             string                  `json:"request_sha256"`
	RequestedCachePlanSHA  string                  `json:"requested_cache_plan_sha256"`
	State                  string                  `json:"state"`
	Error                  string                  `json:"error"`
	Cache                  *WAFCountryCacheEntry   `json:"cache,omitempty"`
	DataOnly               bool                    `json:"data_only"`
	AutomaticReplayAllowed bool                    `json:"automatic_replay_allowed"`
}

func WAFCountryCacheDataset(in WAFCountryDataSelection) string {
	if ValidateWAFCountryDataSelection(in) != nil {
		return ""
	}
	raw, _ := json.Marshal(in.Countries)
	return in.DataManifestSHA + "-" + Hash(string(raw))
}

// Exact canonical bytes shared with Root's durable cache plan protocol.
func WAFCountryCachePlanSHA(job string, in WAFCountryDataSelection) string {
	if !ValidID(job) || ValidateWAFCountryDataSelection(in) != nil {
		return ""
	}
	plan := struct {
		Format          int      `json:"format"`
		JobID           string   `json:"job_id"`
		DataManifestSHA string   `json:"data_manifest_sha256"`
		Countries       []string `json:"countries"`
	}{1, job, in.DataManifestSHA, in.Countries}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return ""
	}
	return Hash(string(append(raw, '\n')))
}

func validWAFCountryDataOperation(out WAFCountryDataOperation, id, actor string, in WAFCountryDataSelection) bool {
	if out.Format != 1 || !ValidID(id) || out.JobID != id || !ValidID(actor) || out.ActorID != actor || !SameWAFCountryDataSelection(out.Selection, in) || !out.DataOnly || out.AutomaticReplayAllowed || !validLowerSHA256(out.RequestSHA) || out.RequestedCachePlanSHA != WAFCountryCachePlanSHA(id, in) || len(out.Error) > 1024 {
		return false
	}
	payload, _ := json.Marshal(in)
	if out.PayloadSHA != Hash(string(payload)) {
		return false
	}
	switch out.State {
	case "queued", "running":
		if out.Error != "" || out.Cache != nil {
			return false
		}
	case "succeeded":
		if out.Error != "" || out.Cache == nil {
			return false
		}
	case "failed", "needs_attention":
		if out.Error == "" {
			return false
		}
	default:
		return false
	}
	if out.Cache == nil {
		return true
	}
	c := out.Cache
	if !c.Published || c.ActivatedNginxPolicy || c.Dataset != WAFCountryCacheDataset(in) || c.DataManifestSHA != in.DataManifestSHA || !reflect.DeepEqual(c.Countries, in.Countries) || c.Release != in.Release || c.Revision != in.Revision || !ValidID(c.OriginalJobID) || c.PlanSHA != WAFCountryCachePlanSHA(c.OriginalJobID, in) || c.Reused != (c.OriginalJobID != id) || c.Bytes < 1 || c.Bytes > 64<<20 || c.Networks < 1 || c.Networks > 1<<20 {
		return false
	}
	stamp, err := time.Parse(time.RFC3339, c.PreparedAt)
	return err == nil && !stamp.IsZero() && stamp.UTC().Format(time.RFC3339) == c.PreparedAt
}

func DecodeWAFCountryDataOperation(raw []byte, id, actor string, in WAFCountryDataSelection) (WAFCountryDataOperation, error) {
	var out WAFCountryDataOperation
	bad := errors.New("国家数据原任务返回身份、完整内容或数据提交证据不符；未认定成功或重发")
	var wire struct {
		Selection json.RawMessage `json:"selection"`
		Cache     json.RawMessage `json:"cache"`
	}
	if len(raw) < 1 || len(raw) > 32<<10 || json.Unmarshal(raw, &wire) != nil {
		return out, bad
	}
	fields := []string{"format", "job_id", "actor_id", "selection", "payload_sha256", "request_sha256", "requested_cache_plan_sha256", "state", "error", "data_only", "automatic_replay_allowed"}
	if len(wire.Cache) > 0 {
		fields = append(fields, "cache")
		if !wafInventoryJSONShape(wire.Cache, []string{"dataset", "data_manifest_sha256", "countries", "release", "revision", "original_job_id", "plan_sha256", "prepared_at", "bytes", "networks", "published", "reused", "activated_nginx_policy"}) {
			return out, bad
		}
	}
	if !wafInventoryJSONShape(raw, fields) || !wafInventoryJSONShape(wire.Selection, wafCountrySelectionFields) || json.Unmarshal(raw, &out) != nil || !validWAFCountryDataOperation(out, id, actor, in) {
		return WAFCountryDataOperation{}, bad
	}
	return out, nil
}
