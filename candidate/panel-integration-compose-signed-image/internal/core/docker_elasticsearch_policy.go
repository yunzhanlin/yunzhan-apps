package core

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"
)

type ElasticsearchSnapshotPolicySettings struct {
	DailyTime  string `json:"daily_time"`
	ExpireDays int    `json:"expire_days"`
	MinCount   int    `json:"min_count"`
	MaxCount   int    `json:"max_count"`
}

func (p ElasticsearchSnapshotPolicySettings) valid() bool {
	return elasticsearchDailyTime.MatchString(p.DailyTime) &&
		p.ExpireDays >= 1 && p.ExpireDays <= 3650 &&
		p.MinCount >= 1 && p.MinCount <= p.MaxCount && p.MaxCount <= 1000
}

type ElasticsearchSnapshotPolicyRequest struct {
	Index    string                               `json:"index"`
	Password string                               `json:"password"`
	Revision string                               `json:"revision,omitempty"`
	Settings *ElasticsearchSnapshotPolicySettings `json:"settings,omitempty"`
}

var elasticsearchDailyTime = regexp.MustCompile(`^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$`)
var elasticsearchPolicyRevision = regexp.MustCompile(`^[1-9][0-9]{0,18}:[1-9][0-9]{0,18}$`)

func (in ElasticsearchSnapshotPolicyRequest) Validate(action string) error {
	if !elasticsearchSnapshotName.MatchString(in.Index) {
		return errors.New("请选择一个具体的索引")
	}
	if !elasticsearchPasswordValid(in.Password) {
		return errors.New("请输入当前 Elasticsearch 管理员密码")
	}
	if in.Revision != "" && !elasticsearchPolicyRevision.MatchString(in.Revision) {
		return errors.New("快照策略版本无效，请重新读取")
	}
	switch action {
	case "read":
		if in.Revision == "" && in.Settings == nil {
			return nil
		}
	case "save":
		if in.Settings != nil && in.Settings.valid() {
			return nil
		}
		return errors.New("请选择有效的 UTC 执行时间、保留天数和快照数量范围")
	case "remove":
		if in.Revision != "" && in.Settings == nil {
			return nil
		}
	}
	return errors.New("快照策略参数无效")
}

type ElasticsearchSnapshotPolicy struct {
	ProjectID           string                               `json:"project_id"`
	Index               string                               `json:"index"`
	Revision            string                               `json:"revision,omitempty"`
	Settings            *ElasticsearchSnapshotPolicySettings `json:"settings,omitempty"`
	NextExecutionMillis int64                                `json:"next_execution_millis,omitempty"`
	LastSuccess         string                               `json:"last_success,omitempty"`
	LastFailure         string                               `json:"last_failure,omitempty"`
}

func (p ElasticsearchSnapshotPolicy) ValidFor(id, index string) bool {
	if p.ProjectID != id || p.Index != index {
		return false
	}
	if p.Settings == nil {
		return p.Revision == "" && p.NextExecutionMillis == 0 && p.LastSuccess == "" && p.LastFailure == ""
	}
	return p.Settings.valid() && elasticsearchPolicyRevision.MatchString(p.Revision) &&
		p.NextExecutionMillis >= 0 &&
		(p.LastSuccess == "" || elasticsearchSnapshotName.MatchString(p.LastSuccess)) &&
		(p.LastFailure == "" || elasticsearchSnapshotName.MatchString(p.LastFailure))
}

func (a *Server) dockerElasticsearchPolicyRoutes(m *http.ServeMux) {
	for _, action := range []string{"read", "save", "remove"} {
		m.HandleFunc("POST /api/docker/projects/{id}/elasticsearch-policies/"+action, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			access, err := a.Store.UserAccess(u.ID)
			if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 {
				fail(w, http.StatusForbidden, "Elasticsearch 快照策略需要完整管理员权限")
				return
			}
			id := r.PathValue("id")
			if !ValidID(id) {
				fail(w, http.StatusBadRequest, "Elasticsearch 项目标识无效")
				return
			}
			var in ElasticsearchSnapshotPolicyRequest
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if !decode(w, r, &in) {
				return
			}
			if err = in.Validate(action); err != nil {
				fail(w, http.StatusBadRequest, err.Error())
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			ctx, cancel := context.WithTimeout(r.Context(), 65*time.Second)
			defer cancel()
			var out ElasticsearchSnapshotPolicy
			if err = a.Executor.Call(ctx, http.MethodPost, "/v1/docker/projects/"+id+"/elasticsearch-policies/"+action, in, &out); err != nil {
				if action != "read" {
					_ = a.Store.Audit(u.Username, "elasticsearch.policy."+action, id+"/"+in.Index, "unconfirmed")
				}
				fail(w, http.StatusConflict, err.Error())
				return
			}
			if !out.ValidFor(id, in.Index) ||
				action == "save" && (out.Settings == nil || *out.Settings != *in.Settings) ||
				action == "remove" && out.Settings != nil {
				fail(w, http.StatusBadGateway, "Elasticsearch 快照策略结果无法核对")
				return
			}
			if action != "read" {
				_ = a.Store.Audit(u.Username, "elasticsearch.policy."+action, id+"/"+in.Index, "confirmed")
			}
			send(w, http.StatusOK, out)
		}))
	}
}
