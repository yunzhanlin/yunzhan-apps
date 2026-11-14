package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	ElasticsearchLegacyTemplate         = "elasticsearch"
	ElasticsearchSnapshotTemplate       = "elasticsearch-snapshot"
	elasticsearchSnapshotAppVersion     = "9.1.4-compat2"
	ElasticsearchSnapshotRepositoryPath = "/usr/share/elasticsearch/logs/yunzhan-snapshots"
)

func IsElasticsearchTemplate(template string) bool {
	return template == ElasticsearchLegacyTemplate || template == ElasticsearchSnapshotTemplate
}

func elasticsearchCompose(template string, port int, password string) string {
	var repository, repositoryMount, repositoryVolume string
	if template == ElasticsearchSnapshotTemplate {
		repository = "\n      path.repo: " + ElasticsearchSnapshotRepositoryPath
		repositoryMount = "\n      - snapshots:/usr/share/elasticsearch/logs"
		repositoryVolume = "\n  snapshots: {}"
	}
	return fmt.Sprintf(`services:
  elasticsearch:
    image: %s
    restart: unless-stopped
    environment:
      discovery.type: single-node
      xpack.security.enabled: "true"
      xpack.security.autoconfiguration.enabled: "false"
      xpack.security.http.ssl.enabled: "false"
      transport.host: "127.0.0.1"
      ELASTIC_PASSWORD: "%s"
      node.store.allow_mmap: "false"%s
      ES_JAVA_OPTS: "-Xms512m -Xmx512m"
    mem_limit: 1g
    ports:
      - "127.0.0.1:%d:9200"
    volumes:
      - data:/usr/share/elasticsearch/data%s
    healthcheck:
      test: ["CMD-SHELL", "test \"$$(curl -sS -o /dev/null -w '%%{http_code}' --max-time 10 http://127.0.0.1:9200/_cluster/health)\" = 401"]
      interval: 15s
      timeout: 15s
      retries: 20
      start_period: 15m
volumes:
  data: {}%s
`, dockerElasticsearchImage, password, repository, port, repositoryMount, repositoryVolume)
}

func ElasticsearchSnapshotComposeMatches(source string, port int, password string) bool {
	return port >= 1024 && port <= 65535 && len(password) == 64 && ValidID(password[:32]) && ValidID(password[32:]) &&
		elasticsearchCompose(ElasticsearchSnapshotTemplate, port, password) == source
}

type ElasticsearchSnapshotRequest struct {
	Index        string `json:"index"`
	Snapshot     string `json:"snapshot"`
	RestoreIndex string `json:"restore_index,omitempty"`
	Password     string `json:"password"`
}

type ElasticsearchSnapshotResult struct {
	ProjectID    string `json:"project_id"`
	Snapshot     string `json:"snapshot"`
	Index        string `json:"index"`
	RestoreIndex string `json:"restore_index,omitempty"`
	State        string `json:"state"`
}

const ElasticsearchSnapshotRepository = "yunzhan-local"
const ElasticsearchSnapshotInventoryPageSize = 20

type ElasticsearchSnapshotInventoryRequest struct {
	Password string `json:"password"`
	Cursor   string `json:"cursor,omitempty"`
}

type ElasticsearchSnapshotInventoryRow struct {
	Snapshot      string   `json:"snapshot"`
	Indices       []string `json:"indices"`
	IndexCount    int      `json:"index_count"`
	State         string   `json:"state"`
	StartedMillis int64    `json:"start_time_in_millis"`
	Restorable    bool     `json:"restorable"`
}

type ElasticsearchSnapshotInventory struct {
	ProjectID       string                              `json:"project_id"`
	RepositoryReady bool                                `json:"repository_ready"`
	Snapshots       []ElasticsearchSnapshotInventoryRow `json:"snapshots"`
	Next            string                              `json:"next,omitempty"`
}

func (in ElasticsearchSnapshotInventoryRequest) Validate() error {
	if !elasticsearchPasswordValid(in.Password) {
		return errors.New("请输入当前 Elasticsearch 管理员密码")
	}
	if len(in.Cursor) > 1024 || !elasticsearchSnapshotCursor.MatchString(in.Cursor) {
		return errors.New("快照分页标识无效")
	}
	return nil
}

func (out ElasticsearchSnapshotInventory) ValidForProject(id string) bool {
	if out.ProjectID != id || out.Snapshots == nil || len(out.Snapshots) > ElasticsearchSnapshotInventoryPageSize ||
		len(out.Next) > 1024 || !elasticsearchSnapshotCursor.MatchString(out.Next) ||
		!out.RepositoryReady && (len(out.Snapshots) != 0 || out.Next != "") {
		return false
	}
	for _, row := range out.Snapshots {
		if len(row.Snapshot) == 0 || len(row.Snapshot) > 1024 || !utf8.ValidString(row.Snapshot) ||
			strings.IndexFunc(row.Snapshot, unicode.IsControl) >= 0 || row.StartedMillis < 0 || len(row.Indices) > 16 ||
			row.IndexCount < len(row.Indices) || len(row.Indices) < 16 && row.IndexCount != len(row.Indices) {
			return false
		}
		for _, index := range row.Indices {
			if len(index) == 0 || len(index) > 255 || !utf8.ValidString(index) || strings.IndexFunc(index, unicode.IsControl) >= 0 {
				return false
			}
		}
		switch row.State {
		case "IN_PROGRESS", "SUCCESS", "FAILED", "PARTIAL", "INCOMPATIBLE":
		default:
			return false
		}
		if row.Restorable != row.CanRestore() {
			return false
		}
	}
	return true
}

func (row ElasticsearchSnapshotInventoryRow) CanRestore() bool {
	return row.State == "SUCCESS" && row.IndexCount == 1 && len(row.Indices) == 1 &&
		elasticsearchSnapshotName.MatchString(row.Snapshot) && elasticsearchSnapshotName.MatchString(row.Indices[0])
}

var elasticsearchSnapshotCursor = regexp.MustCompile(`^[a-zA-Z0-9_+=/-]*$`)
var elasticsearchSnapshotName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,79}$`)
var elasticsearchRestoreIndex = regexp.MustCompile(`^restored-[a-z0-9][a-z0-9_-]{0,36}-[a-f0-9]{32}$`)

func (in ElasticsearchSnapshotRequest) Validate(restore bool) error {
	if !elasticsearchSnapshotName.MatchString(in.Index) || !elasticsearchSnapshotName.MatchString(in.Snapshot) ||
		(restore && (!elasticsearchRestoreIndex.MatchString(in.RestoreIndex) || in.Index == in.RestoreIndex)) ||
		(!restore && in.RestoreIndex != "") {
		return errors.New("请输入明确的索引和快照名称。恢复目标必须是面板生成的新索引名")
	}
	if !elasticsearchPasswordValid(in.Password) {
		return errors.New("请输入当前 Elasticsearch 管理员密码")
	}
	return nil
}

func elasticsearchPasswordValid(password string) bool {
	return len(password) > 0 && len(password) <= 512 && utf8.ValidString(password) &&
		strings.IndexFunc(password, unicode.IsControl) < 0
}

func (a *Server) dockerElasticsearchRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/docker/projects/{id}/elasticsearch-snapshots/inventory", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		access, err := a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 {
			fail(w, http.StatusForbidden, "Elasticsearch 快照需要完整管理员权限")
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, http.StatusBadRequest, "Elasticsearch 项目标识无效")
			return
		}
		var in ElasticsearchSnapshotInventoryRequest
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if !decode(w, r, &in) {
			return
		}
		if err = in.Validate(); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), 65*time.Second)
		defer cancel()
		var out ElasticsearchSnapshotInventory
		if err = a.Executor.Call(ctx, http.MethodPost, "/v1/docker/projects/"+id+"/elasticsearch-snapshots/inventory", in, &out); err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		if !out.ValidForProject(id) {
			fail(w, http.StatusBadGateway, "Elasticsearch 快照清单无法核对")
			return
		}
		send(w, http.StatusOK, out)
	}))

	for _, action := range []string{"create", "restore", "status"} {
		m.HandleFunc("POST /api/docker/projects/{id}/elasticsearch-snapshots/"+action, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			access, err := a.Store.UserAccess(u.ID)
			if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 {
				fail(w, http.StatusForbidden, "Elasticsearch 快照需要完整管理员权限")
				return
			}
			id := r.PathValue("id")
			if !ValidID(id) {
				fail(w, http.StatusBadRequest, "Elasticsearch 项目标识无效")
				return
			}
			var in ElasticsearchSnapshotRequest
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if !decode(w, r, &in) {
				return
			}
			if err = in.Validate(action == "restore" || action == "status" && in.RestoreIndex != ""); err != nil {
				fail(w, http.StatusBadRequest, err.Error())
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			ctx, cancel := context.WithTimeout(r.Context(), 65*time.Second)
			defer cancel()
			var out ElasticsearchSnapshotResult
			err = a.Executor.Call(ctx, http.MethodPost, "/v1/docker/projects/"+id+"/elasticsearch-snapshots/"+action, in, &out)
			if err != nil {
				_ = a.Store.Audit(u.Username, "elasticsearch.snapshot."+action, id, "unconfirmed")
				fail(w, http.StatusConflict, err.Error())
				return
			}
			if out.ProjectID != id || out.Snapshot != in.Snapshot || out.Index != in.Index ||
				out.RestoreIndex != in.RestoreIndex || !out.ValidState(action) {
				fail(w, http.StatusBadGateway, "Elasticsearch 快照操作结果待核对")
				return
			}
			if action == "status" {
				send(w, http.StatusOK, out)
				return
			}
			_ = a.Store.Audit(u.Username, "elasticsearch.snapshot."+action, id, "accepted")
			send(w, http.StatusAccepted, out)
		}))
	}
}

func (result ElasticsearchSnapshotResult) ValidState(action string) bool {
	if action != "status" {
		return result.State == "accepted"
	}
	switch result.State {
	case "missing", "running", "complete", "failed":
		return true
	default:
		return false
	}
}
