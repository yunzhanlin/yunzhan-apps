package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"local/panel/internal/core"
)

type elasticsearchSLMDefinition struct {
	Name       string         `json:"name"`
	Repository string         `json:"repository"`
	Schedule   string         `json:"schedule"`
	Config     map[string]any `json:"config"`
	Retention  struct {
		ExpireAfter string `json:"expire_after"`
		MinCount    int    `json:"min_count"`
		MaxCount    int    `json:"max_count"`
	} `json:"retention"`
}

func elasticsearchPolicyName(project, index string) string {
	digest := sha256.Sum256([]byte(project + "/" + index))
	return "yunzhan-" + hex.EncodeToString(digest[:16])
}

func elasticsearchPolicyDefinition(project, index string, settings core.ElasticsearchSnapshotPolicySettings) elasticsearchSLMDefinition {
	hour, _ := strconv.Atoi(settings.DailyTime[:2])
	minute, _ := strconv.Atoi(settings.DailyTime[3:])
	out := elasticsearchSLMDefinition{
		Name: elasticsearchPolicyName(project, index), Repository: core.ElasticsearchSnapshotRepository,
		Schedule: "0 " + strconv.Itoa(minute) + " " + strconv.Itoa(hour) + " * * ?",
		Config: map[string]any{
			"indices": []any{index}, "ignore_unavailable": false, "include_global_state": false,
			"feature_states": []any{"none"}, "partial": false,
			"metadata": map[string]any{"yunzhan_project": project, "yunzhan_index": index},
		},
	}
	out.Retention.ExpireAfter = strconv.Itoa(settings.ExpireDays) + "d"
	out.Retention.MinCount = settings.MinCount
	out.Retention.MaxCount = settings.MaxCount
	return out
}

func parseElasticsearchPolicy(project, index string, policy elasticsearchSLMDefinition) (core.ElasticsearchSnapshotPolicySettings, error) {
	var out core.ElasticsearchSnapshotPolicySettings
	fields := strings.Split(policy.Schedule, " ")
	bad := errors.New("同名快照策略由外部管理或已被修改")
	if len(fields) != 6 {
		return out, bad
	}
	minute, errMinute := strconv.Atoi(fields[1])
	hour, errHour := strconv.Atoi(fields[2])
	daysValue := strings.TrimSuffix(policy.Retention.ExpireAfter, "d")
	days, errDays := strconv.Atoi(daysValue)
	if errMinute != nil || errHour != nil || errDays != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return out, bad
	}
	out = core.ElasticsearchSnapshotPolicySettings{
		DailyTime:  time.Date(2000, time.January, 1, hour, minute, 0, 0, time.UTC).Format("15:04"),
		ExpireDays: days, MinCount: policy.Retention.MinCount, MaxCount: policy.Retention.MaxCount,
	}
	// Accept only the precise definition that the panel can generate.
	expected := elasticsearchPolicyDefinition(project, index, out)
	if !reflect.DeepEqual(expected, policy) {
		return out, bad
	}
	return out, nil
}

type elasticsearchSLMPolicyInfo struct {
	Policy   elasticsearchSLMDefinition `json:"policy"`
	Version  int64                      `json:"version"`
	Modified int64                      `json:"modified_date_millis"`
	Next     int64                      `json:"next_execution_millis"`
	Success  struct {
		Name string `json:"snapshot_name"`
	} `json:"last_success"`
	Failure struct {
		Name string `json:"snapshot_name"`
	} `json:"last_failure"`
}

func (c elasticsearchSnapshotHTTP) readPolicy(ctx context.Context, project, index string) (core.ElasticsearchSnapshotPolicy, error) {
	out := core.ElasticsearchSnapshotPolicy{ProjectID: project, Index: index}
	name := elasticsearchPolicyName(project, index)
	var response map[string]elasticsearchSLMPolicyInfo
	status, err := c.call(ctx, http.MethodGet, "/_slm/policy/"+name+"?master_timeout=4s", nil, &response)
	if err != nil {
		return out, err
	}
	if status == http.StatusNotFound {
		return out, nil
	}
	row, found := response[name]
	if status != http.StatusOK || !found || len(response) != 1 {
		return out, errors.New("无法读取 Elasticsearch 快照策略")
	}
	settings, err := parseElasticsearchPolicy(project, index, row.Policy)
	if err != nil {
		return out, err
	}
	out.Settings = &settings
	out.Revision = strconv.FormatInt(row.Version, 10) + ":" + strconv.FormatInt(row.Modified, 10)
	if row.Next > 0 {
		out.NextExecutionMillis = row.Next
	}
	out.LastSuccess = row.Success.Name
	out.LastFailure = row.Failure.Name
	if !out.ValidFor(project, index) {
		return out, errors.New("Elasticsearch 返回了无效的快照策略版本")
	}
	return out, nil
}

func (c elasticsearchSnapshotHTTP) applyPolicy(ctx context.Context, project string, in core.ElasticsearchSnapshotPolicyRequest, action string) (core.ElasticsearchSnapshotPolicy, error) {
	current, err := c.readPolicy(ctx, project, in.Index)
	if err != nil || action == "read" {
		return current, err
	}
	if current.Revision != in.Revision {
		return current, errors.New("快照策略已变更，请重新读取")
	}

	method := http.MethodDelete
	var definition any
	if action == "save" {
		if current.Settings != nil && *current.Settings == *in.Settings {
			return current, nil
		}
		exists, err := c.indexExists(ctx, in.Index)
		if err != nil {
			return current, err
		}
		if !exists {
			return current, errors.New("所选 Elasticsearch 索引不存在")
		}
		if err := c.verifyRepository(ctx, true); err != nil {
			return current, err
		}
		method = http.MethodPut
		definition = elasticsearchPolicyDefinition(project, in.Index, *in.Settings)
	}
	var ack struct {
		Acknowledged bool `json:"acknowledged"`
	}
	name := elasticsearchPolicyName(project, in.Index)
	status, err := c.call(ctx, method, "/_slm/policy/"+name+"?master_timeout=4s&timeout=4s", definition, &ack)
	if err != nil || status != http.StatusOK || !ack.Acknowledged {
		return current, errors.New("快照策略结果待核对，请重新读取")
	}
	final, err := c.readPolicy(ctx, project, in.Index)
	if err != nil || action == "save" && (final.Settings == nil || *final.Settings != *in.Settings) ||
		action == "remove" && final.Settings != nil {
		return current, errors.New("快照策略结果待核对，请重新读取")
	}
	return final, nil
}

func dockerElasticsearchPolicyRoutes(m *http.ServeMux) {
	for _, action := range []string{"read", "save", "remove"} {
		m.HandleFunc("POST /v1/docker/projects/{id}/elasticsearch-policies/"+action, func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var in core.ElasticsearchSnapshotPolicyRequest
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if !readJSON(w, r, &in) {
				return
			}
			if !core.ValidID(id) || in.Validate(action) != nil {
				respond(w, http.StatusBadRequest, map[string]string{"error": "Elasticsearch 快照策略参数无效"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 58*time.Second)
			defer cancel()
			var out core.ElasticsearchSnapshotPolicy
			err := withDockerMutation(ctx, func(bound context.Context) error {
				return withElasticsearchSnapshotProject(bound, id, in.Password, func(client elasticsearchSnapshotHTTP) error {
					var err error
					out, err = client.applyPolicy(bound, id, in, action)
					return err
				})
			})
			if err != nil {
				respond(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			respond(w, http.StatusOK, out)
		})
	}
}
