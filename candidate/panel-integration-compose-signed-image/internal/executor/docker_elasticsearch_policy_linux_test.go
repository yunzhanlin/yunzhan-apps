package executor

import (
	"encoding/json"
	"testing"

	"local/panel/internal/core"
)

func TestElasticsearchPolicyRejectsExternalConfiguration(t *testing.T) {
	const project = "42b8614011e14d60934ba692ba6140e3"
	const index = "sales"
	policy := core.ElasticsearchSnapshotPolicySettings{DailyTime: "02:05", ExpireDays: 7, MinCount: 1, MaxCount: 4}
	raw, err := json.Marshal(elasticsearchPolicyDefinition(project, index, policy))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*elasticsearchSLMDefinition)
	}{
		{"owned round trip", nil},
		{"other repository", func(p *elasticsearchSLMDefinition) { p.Repository = "other" }},
		{"unrestricted scope", func(p *elasticsearchSLMDefinition) { p.Config["indices"] = []any{"*"} }},
		{"external metadata", func(p *elasticsearchSLMDefinition) {
			p.Config["metadata"].(map[string]any)["yunzhan_project"] = "other"
		}},
		{"global state", func(p *elasticsearchSLMDefinition) { p.Config["include_global_state"] = true }},
		{"non-daily expression", func(p *elasticsearchSLMDefinition) { p.Schedule = "0 5 2 * * MON" }},
		{"noncanonical duration", func(p *elasticsearchSLMDefinition) { p.Retention.ExpireAfter = "168h" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var in elasticsearchSLMDefinition
			if err := json.Unmarshal(raw, &in); err != nil {
				t.Fatal(err)
			}
			if test.change != nil {
				test.change(&in)
			}
			got, err := parseElasticsearchPolicy(project, index, in)
			if test.change == nil {
				if err != nil || got != policy {
					t.Fatalf("policy = %+v error = %v", got, err)
				}
			} else if err == nil {
				t.Fatal("accepted a policy with an unexpected definition")
			}
		})
	}
}

func TestElasticsearchPolicyInputBounds(t *testing.T) {
	settings := core.ElasticsearchSnapshotPolicySettings{DailyTime: "23:59", ExpireDays: 1, MinCount: 1, MaxCount: 1}
	in := core.ElasticsearchSnapshotPolicyRequest{Index: "sales", Password: "secret", Settings: &settings}
	if err := in.Validate("save"); err != nil {
		t.Fatal(err)
	}
	in.Settings.MaxCount = 0
	if in.Validate("save") == nil {
		t.Fatal("accepted maximum below minimum")
	}
	in.Settings = nil
	if in.Validate("remove") == nil || in.Validate("read") != nil {
		t.Fatal("policy removal must name the observed revision")
	}
	in.Revision = "2:443"
	if in.Validate("remove") != nil || in.Validate("read") == nil {
		t.Fatal("unexpected revision handling")
	}
}
