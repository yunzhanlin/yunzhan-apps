//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"local/panel/internal/core"
)

var errDockerContainerState = errors.New("Docker 返回的容器身份或运行状态无法核对")

type dockerStateSnapshot struct {
	ID                 string     `json:"id"`
	ObservedAt         time.Time  `json:"observed_at"`
	Status             string     `json:"status"`
	StartedAt          *time.Time `json:"started_at"`
	FinishedAt         *time.Time `json:"finished_at"`
	ExitCode           *int       `json:"exit_code"`
	OOMKilled          bool       `json:"oom_killed"`
	RestartCount       int        `json:"restart_count"`
	RestartPolicy      string     `json:"restart_policy"`
	MaximumRetryCount  int        `json:"maximum_retry_count"`
	Health             *string    `json:"health"`
	HealthFailureCount *int       `json:"health_failure_count"`
}

// Inspect includes environment variables, mount paths and probe output. Parse
// only the exact needed fields and never return arbitrary daemon strings.
func decodeDockerContainerState(raw []byte, id string, now time.Time) (dockerStateSnapshot, error) {
	root, err := dockerPullJSONObject(raw)
	if err != nil {
		return dockerStateSnapshot{}, errDockerContainerState
	}
	actual, ok := dockerPullJSONString(root["Id"])
	var restartCount *int
	if !ok || !core.ValidDockerContainerID(id) || actual != id ||
		json.Unmarshal(root["RestartCount"], &restartCount) != nil || restartCount == nil || *restartCount < 0 {
		return dockerStateSnapshot{}, errDockerContainerState
	}
	state, err := dockerPullJSONObject(root["State"])
	if err != nil {
		return dockerStateSnapshot{}, errDockerContainerState
	}
	host, err := dockerPullJSONObject(root["HostConfig"])
	if err != nil {
		return dockerStateSnapshot{}, errDockerContainerState
	}
	policy, err := dockerPullJSONObject(host["RestartPolicy"])
	if err != nil {
		return dockerStateSnapshot{}, errDockerContainerState
	}
	view := dockerStateSnapshot{ID: actual, ObservedAt: now.UTC(), RestartCount: *restartCount}
	view.Status, _ = dockerPullJSONString(state["Status"])
	switch view.Status {
	case "created", "running", "paused", "restarting", "exited", "dead", "removing":
	default:
		return dockerStateSnapshot{}, errDockerContainerState
	}
	view.RestartPolicy, ok = dockerPullJSONString(policy["Name"])
	if !ok {
		return dockerStateSnapshot{}, errDockerContainerState
	}
	switch view.RestartPolicy {
	case "", "no":
		view.RestartPolicy = "no"
	case "always", "unless-stopped", "on-failure":
	default:
		return dockerStateSnapshot{}, errDockerContainerState
	}
	var retries, exit *int
	var killed *bool
	if json.Unmarshal(policy["MaximumRetryCount"], &retries) != nil || retries == nil || *retries < 0 ||
		json.Unmarshal(state["ExitCode"], &exit) != nil || exit == nil || *exit < 0 ||
		json.Unmarshal(state["OOMKilled"], &killed) != nil || killed == nil {
		return dockerStateSnapshot{}, errDockerContainerState
	}
	view.MaximumRetryCount, view.OOMKilled = *retries, *killed
	for _, field := range []struct {
		key string
		out **time.Time
	}{{"StartedAt", &view.StartedAt}, {"FinishedAt", &view.FinishedAt}} {
		value, ok := dockerPullJSONString(state[field.key])
		stamp, err := time.Parse(time.RFC3339Nano, value)
		if !ok || err != nil {
			return dockerStateSnapshot{}, errDockerContainerState
		}
		if !stamp.IsZero() {
			stamp = stamp.UTC()
			*field.out = &stamp
		}
	}
	if view.FinishedAt != nil && view.Status != "running" && view.Status != "paused" {
		view.ExitCode = exit
	}
	if value := state["Health"]; len(value) > 0 && !bytes.Equal(value, []byte("null")) {
		health, err := dockerPullJSONObject(value)
		if err != nil {
			return dockerStateSnapshot{}, errDockerContainerState
		}
		status, _ := dockerPullJSONString(health["Status"])
		switch status {
		case "none", "starting", "healthy", "unhealthy":
		default:
			return dockerStateSnapshot{}, errDockerContainerState
		}
		var failures *int
		if json.Unmarshal(health["FailingStreak"], &failures) != nil || failures == nil || *failures < 0 {
			return dockerStateSnapshot{}, errDockerContainerState
		}
		view.Health, view.HealthFailureCount = &status, failures
	}
	return view, nil
}

func dockerContainerState(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !core.ValidDockerContainerID(id) {
		respond(w, http.StatusBadRequest, map[string]string{"error": "容器标识无效"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, 2<<20)
	if err != nil {
		respond(w, http.StatusConflict, map[string]string{"error": "无法读取指定容器的当前运行状态"})
		return
	}
	view, err := decodeDockerContainerState(raw, id, time.Now())
	if err != nil {
		respond(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, http.StatusOK, view)
}
