//go:build linux

package executor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDockerContainerStateOnlyReportsVerifiedOperationalFields(t *testing.T) {
	id := strings.Repeat("a", 64)
	raw := `{
		"Id":"` + id + `",
		"RestartCount":3,
		"State":{"Status":"exited","StartedAt":"2026-11-14T09:00:00.123456789Z",
			"FinishedAt":"2026-11-14T09:01:00.123456789Z","ExitCode":137,
			"OOMKilled":true,"Error":"private-daemon-error",
			"Health":{"Status":"unhealthy","FailingStreak":4,"Log":[{"Output":"private-health-log"}]}},
		"HostConfig":{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":5}},
		"Config":{"Env":["PRIVATE=private-config"],"Labels":{"other":"private-label"}},
		"Mounts":[{"Source":"/private-mount"}]
	}`
	when := time.Date(2026, 11, 14, 9, 2, 0, 0, time.UTC)
	snapshot, err := decodeDockerContainerState([]byte(raw), id, when)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ID != id || snapshot.Status != "exited" || !snapshot.ObservedAt.Equal(when) ||
		snapshot.StartedAt == nil || snapshot.FinishedAt == nil || snapshot.ExitCode == nil || *snapshot.ExitCode != 137 ||
		!snapshot.OOMKilled || snapshot.RestartCount != 3 || snapshot.RestartPolicy != "on-failure" ||
		snapshot.MaximumRetryCount != 5 || snapshot.Health == nil || *snapshot.Health != "unhealthy" ||
		snapshot.HealthFailureCount == nil || *snapshot.HealthFailureCount != 4 {
		t.Fatalf("unexpected lifecycle observation: %+v", snapshot)
	}
	out, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(out), "private-") {
		t.Fatal("sensitive daemon fields leaked", err)
	}
	running := strings.Replace(raw, `"Status":"exited"`, `"Status":"running"`, 1)
	running = strings.Replace(running, `"FinishedAt":"2026-11-14T09:01:00.123456789Z"`, `"FinishedAt":"0001-01-01T00:00:00Z"`, 1)
	snapshot, err = decodeDockerContainerState([]byte(running), id, when)
	if err != nil || snapshot.ExitCode != nil || snapshot.FinishedAt != nil {
		t.Fatal("running container reported a completed exit", err)
	}
}

func TestDockerContainerStateRejectsMissingAndAmbiguousReadings(t *testing.T) {
	id := strings.Repeat("b", 64)
	raw := `{"Id":"` + id + `","RestartCount":0,
		"State":{"Status":"created","StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z","ExitCode":0,"OOMKilled":false,"Health":null},
		"HostConfig":{"RestartPolicy":{"Name":"","MaximumRetryCount":0}}}`
	snapshot, err := decodeDockerContainerState([]byte(raw), id, time.Now())
	if err != nil || snapshot.StartedAt != nil || snapshot.FinishedAt != nil || snapshot.ExitCode != nil ||
		snapshot.Health != nil || snapshot.HealthFailureCount != nil || snapshot.RestartPolicy != "no" {
		t.Fatal("new container does not have historical observations", err)
	}
	for _, change := range [][2]string{
		{`"Id"`, `"id"`},
		{id, strings.Repeat("d", 64)},
		{`"RestartCount":0`, `"RestartCount":null`},
		{`"Status":"created"`, `"Status":"created","status":"running"`},
		{`"OOMKilled":false`, `"OomKilled":false`},
		{`"ExitCode":0`, `"ExitCode":-1`},
		{`"Health":null`, `"Health":{"Status":"healthy"}`},
		{`"Name":""`, `"Name":"invalid"`},
		{`"MaximumRetryCount":0`, `"MaximumRetryCount":-1`},
	} {
		changed := strings.Replace(raw, change[0], change[1], 1)
		if _, err := decodeDockerContainerState([]byte(changed), id, time.Now()); err == nil {
			t.Fatal("accepted corrupt or foreign observation after replacing", change[0])
		}
	}
}
