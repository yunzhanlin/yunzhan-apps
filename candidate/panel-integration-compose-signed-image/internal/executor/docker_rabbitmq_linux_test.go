//go:build linux

package executor

import (
	"slices"
	"strings"
	"testing"
)

func TestRabbitMQQueueReportKeepsObservedCountsAndRejectsDamagedRows(t *testing.T) {
	hosts, err := rabbitMQVHosts([]byte(`[{"name":"运维"},{"name":"/"}]`))
	if err != nil || !slices.Equal(hosts, []string{"/", "运维"}) {
		t.Fatalf("unexpected broker vhosts: %v, %v", hosts, err)
	}
	ready := `{"name":"pending","type":"classic","state":"running","durable":true,"messages_ready":2,"messages_unacknowledged":1,"consumers":1}`
	unknown := `{"name":"unavailable","type":"quorum","state":"down","durable":true}`
	rows, err := rabbitMQQueues([]byte("[" + ready + "," + unknown + "]"))
	if err != nil || len(rows) != 2 || rows[0].Name != "pending" || *rows[0].Ready != 2 ||
		*rows[0].Unacknowledged != 1 || *rows[0].Consumers != 1 || rows[1].Ready != nil {
		t.Fatalf("unexpected broker counters: %v, %v", rows, err)
	}
	for _, input := range []string{"null", "[" + ready + "," + ready + "]",
		"[" + strings.Replace(ready, `"messages_ready":2`, `"messages_ready":-2`, 1) + "]",
		"[" + strings.Replace(ready, `"name":"pending"`, `"name":"one","Name":"two"`, 1) + "]",
		"[" + strings.Replace(ready, `"durable":true`, `"durable":null`, 1) + "]"} {
		if _, err := rabbitMQQueues([]byte(input)); err == nil {
			t.Fatalf("unexpectedly accepted %s", input)
		}
	}
	empty, err := rabbitMQQueues([]byte("[]"))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("valid empty inventory was not distinguished from failure: %v, %v", empty, err)
	}
}
