//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"local/panel/internal/core"
)

func validateMemcachedUnixRetirementIssued(seed memcachedUnixControlSeed, issued memcachedUnixControlIssued) error {
	raw, err := json.Marshal(seed)
	if err != nil || seed.Operation.Input.Action != "retire" {
		return core.ErrMemcachedUnixControl
	}
	if _, err = memcachedUnixControlDecodeSeed(raw); err != nil {
		return err
	}
	if issued.Format != 1 || issued.SeedSHA256 != core.Hash(string(raw)) || len(issued.ContainerID) != 64 || !dockerObjectPattern.MatchString(issued.ContainerID) || issued.InitialPID != 0 || issued.InitialStartedAt == "" || len(issued.InitialStartedAt) > 64 {
		return core.ErrMemcachedUnixControl
	}
	if _, err = time.Parse(time.RFC3339Nano, issued.InitialStartedAt); err != nil {
		return core.ErrMemcachedUnixControl
	}
	return nil
}

// Evidence framing only: the caller STILL needs the original signed committed
// installation, current Core grant, original issued journal and held engine
// capability. This function has no DELETE/POST, account/path repair or retry.
// A bare 404, missing list, warning or partial engine response is NOT absence.
func memcachedUnixRetirementAbsence(ctx context.Context, seed memcachedUnixControlSeed, issued memcachedUnixControlIssued, read memcachedRetentionCall) (string, error) {
	refuse := func() (string, error) { return "", core.ErrMemcachedUnixControl }
	if ctx == nil || ctx.Err() != nil || read == nil || validateMemcachedUnixRetirementIssued(seed, issued) != nil {
		return refuse()
	}
	status, body, e := read(ctx, http.MethodGet, "/containers/"+issued.ContainerID+"/json", nil)
	if e != nil || status != http.StatusNotFound || len(body) > 1024 || memcachedDaemonJSON(body) != nil {
		return refuse()
	}
	var fields map[string]json.RawMessage
	var message string
	if json.Unmarshal(body, &fields) != nil || len(fields) != 1 || json.Unmarshal(fields["message"], &message) != nil || message != "No such container: "+issued.ContainerID {
		return refuse()
	}
	filter, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=panel_" + seed.Operation.ProjectID[:12]}})
	query := "filters=" + url.QueryEscape(string(filter))
	for _, path := range []string{"/containers/json?all=1&" + query, "/networks?" + query, "/volumes?" + query} {
		status, body, e = read(ctx, http.MethodGet, path, nil)
		if e != nil || status != http.StatusOK || len(body) > 16<<10 || memcachedDaemonJSON(body) != nil || ctx.Err() != nil {
			return refuse()
		}
		if path[:8] != "/volumes" {
			var items []json.RawMessage
			if len(bytes.TrimSpace(body)) == 0 || bytes.TrimSpace(body)[0] != '[' || json.Unmarshal(body, &items) != nil || len(items) != 0 {
				return refuse()
			}
			continue
		}
		var v map[string]json.RawMessage
		if json.Unmarshal(body, &v) != nil {
			return refuse()
		}
		volumes, ok := v["Volumes"]
		if !ok {
			return refuse()
		}
		for _, item := range []json.RawMessage{volumes, v["Warnings"]} {
			if len(item) == 0 || bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
				continue
			}
			var values []json.RawMessage
			if len(bytes.TrimSpace(item)) == 0 || bytes.TrimSpace(item)[0] != '[' || json.Unmarshal(item, &values) != nil || len(values) != 0 {
				return refuse()
			}
		}
	}
	if ctx.Err() != nil {
		return refuse()
	}
	return memcachedUnixRetirementFingerprint(seed, issued)
}

// Bind the immutable receipt to this exact original installation and CID.
// This digest describes framing, not current engine absence or authority.
func memcachedUnixRetirementFingerprint(seed memcachedUnixControlSeed, issued memcachedUnixControlIssued) (string, error) {
	if validateMemcachedUnixRetirementIssued(seed, issued) != nil {
		return "", core.ErrMemcachedUnixControl
	}
	proof := struct {
		Format                int    `json:"format"`
		ProjectID             string `json:"project_id"`
		ContainerID           string `json:"container_id"`
		InstalledRecordSHA256 string `json:"installed_record_sha256"`
		Engine                string `json:"engine"`
		State                 string `json:"state"`
	}{1, seed.Operation.ProjectID, issued.ContainerID, seed.InstalledRecordSHA256, "panel_" + seed.Operation.ProjectID[:12], "retired"}
	evidence, e := json.Marshal(proof)
	if e != nil {
		return "", core.ErrMemcachedUnixControl
	}
	return core.Hash(string(evidence)), nil
}
