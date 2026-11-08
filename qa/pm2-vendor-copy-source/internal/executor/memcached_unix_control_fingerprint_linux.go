//go:build linux

package executor

import (
	"encoding/json"
	"strings"
	"time"

	"local/panel/internal/core"
)

// Stable precondition for a deliberate control, not a health/authority token.
// Docker health log clocks change naturally and cannot rotate this identity.
// Full source/image/resources/kernel/peer checks remain independently required.
func memcachedUnixRuntimeFingerprint(raw json.RawMessage) (string, error) {
	var value struct {
		ID    string `json:"Id"`
		Image string `json:"Image"`
		State struct {
			Pid        int    `json:"Pid"`
			Running    *bool  `json:"Running"`
			StartedAt  string `json:"StartedAt"`
			FinishedAt string `json:"FinishedAt"`
		} `json:"State"`
	}
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &value) != nil || len(value.ID) != 64 || !dockerObjectPattern.MatchString(value.ID) || !strings.HasPrefix(value.Image, "sha256:") || len(value.Image) != 71 || !composeRequestSHAPattern.MatchString(strings.TrimPrefix(value.Image, "sha256:")) || value.State.Running == nil || value.State.Pid < 0 || *value.State.Running && value.State.Pid < 2 || !*value.State.Running && value.State.Pid != 0 {
		return "", core.ErrMemcachedUnixControl
	}
	for _, stamp := range []string{value.State.StartedAt, value.State.FinishedAt} {
		if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
			return "", core.ErrMemcachedUnixControl
		}
	}
	canonical, _ := json.Marshal(struct {
		Format   int `json:"format"`
		Identity any `json:"identity"`
	}{1, value})
	return core.Hash(string(canonical)), nil
}
