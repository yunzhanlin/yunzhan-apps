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

func TestRabbitMQMigrationRequiresSingleOriginalNode(t *testing.T) {
	const single = `{"disk_nodes":["rabbit@cloudstack-rabbitmq"],"ram_nodes":[],"running_nodes":["rabbit@cloudstack-rabbitmq"],
		"alarms":[],"partitions":{},"versions":{"rabbit@cloudstack-rabbitmq":{"rabbitmq_version":"4.1.4"}}}`
	version, alarms, err := rabbitMQMigrationCluster([]byte(single))
	if err != nil || alarms != 0 || version != "4.1.4" {
		t.Fatalf("unexpected original cluster: %s, %d, %v", version, alarms, err)
	}
	_, alarms, err = rabbitMQMigrationCluster([]byte(strings.Replace(single, `"alarms":[]`,
		`"alarms":[{"resource":"memory","node":"rabbit@cloudstack-rabbitmq"}]`, 1)))
	if err != nil || alarms != 1 {
		t.Fatalf("arrival of an alarm was not visible: %d, %v", alarms, err)
	}
	for _, changed := range []string{
		strings.Replace(single, `"ram_nodes":[]`, `"ram_nodes":["rabbit@different"]`, 1),
		strings.Replace(single, `"partitions":{}`, `"partitions":{"node":["another"]}`, 1),
		strings.Replace(single, `"4.1.4"`, `"4.4.0"`, 1),
		strings.Replace(single, `"alarms":[]`, `"alarms":null`, 1),
	} {
		if _, _, err := rabbitMQMigrationCluster([]byte(changed)); err == nil {
			t.Fatalf("accepted unsupported cluster %s", changed)
		}
	}
}

func TestRabbitMQMigrationReportsDisabledStableFlags(t *testing.T) {
	raw := []byte(`[
		{"name":"zz_stable","state":"disabled","stability":"stable"},
		{"name":"beta","state":"disabled","stability":"experimental"},
		{"name":"aa_required","state":"unsupported","stability":"required"},
		{"name":"enabled_required","state":"enabled","stability":"required"}
	]`)
	got, err := rabbitMQMigrationFeatures(raw)
	if err != nil || !slices.Equal(got, []string{"aa_required", "zz_stable"}) {
		t.Fatalf("wrong features: %v, %v", got, err)
	}
	for _, changed := range []string{
		strings.Replace(string(raw), "beta", "zz_stable", 1),
		strings.Replace(string(raw), "unsupported", "unknown", 1),
		strings.Replace(string(raw), "experimental", "pending", 1),
	} {
		if _, err := rabbitMQMigrationFeatures([]byte(changed)); err == nil {
			t.Fatalf("accepted invalid features %s", changed)
		}
	}
}

func TestRabbitMQ44ClusterWithoutRAMNodes(t *testing.T) {
	const exact = `{"disk_nodes":["rabbit@cloudstack-rabbitmq"],"running_nodes":["rabbit@cloudstack-rabbitmq"],"alarms":[],"partitions":{},"versions":{"rabbit@cloudstack-rabbitmq":{"rabbitmq_version":"4.4.0"}}}`
	if got, alarms, err := rabbitMQClusterVersion([]byte(exact), "4.4.0"); err != nil || got != "4.4.0" || alarms != 0 {
		t.Fatalf("4.4 cluster_status schema: version=%q alarms=%d err=%v", got, alarms, err)
	}
	if _, _, err := rabbitMQClusterVersion([]byte(strings.Replace(exact, "4.4.0", "4.2.9", 1)), "4.2.9"); err == nil {
		t.Fatal("missing RAM node information accepted on 4.2")
	}
	for _, invalid := range []string{`"ram_nodes":null,`, `"ram_nodes":["rabbit@unexpected"],`, `"ram_nodes":{},`} {
		if _, _, err := rabbitMQClusterVersion([]byte("{"+invalid+exact[1:]), "4.4.0"); err == nil {
			t.Fatalf("ambiguous RAM node information accepted: %s", invalid)
		}
	}
}
