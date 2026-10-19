package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/geodata"
)

const StatisticsGeoVersion = "2.6.0"

type StatisticsGeoSelection struct {
	Action          string `json:"action"`
	AppVersion      string `json:"app_version"`
	AppManifestSHA  string `json:"app_manifest_sha256"`
	InstallationID  string `json:"installation_id"`
	Release         string `json:"release"`
	DataManifestSHA string `json:"data_manifest_sha256"`
}
type StatisticsGeoOperation struct {
	JobID     string                 `json:"job_id"`
	Selection StatisticsGeoSelection `json:"selection"`
	State     string                 `json:"state"`
	Error     string                 `json:"error,omitempty"`
	Steps     []Step                 `json:"steps"`
}
type StatisticsGeoStored struct {
	Release     string `json:"release"`
	ManifestSHA string `json:"manifest_sha256"`
	AppSHA      string `json:"app_manifest_sha256"`
	Selected    bool   `json:"selected"`
	Archived    bool   `json:"archived"`
	Previous    bool   `json:"previous"`
	HighWater   bool   `json:"high_water"`
}
type StatisticsGeoState struct {
	Installed      bool                  `json:"installed"`
	AppVersion     string                `json:"app_version"`
	InstallationID string                `json:"installation_id"`
	Selected       string                `json:"selected"`
	Stored         []StatisticsGeoStored `json:"stored"`
	Metadata       geodata.Metadata      `json:"metadata"`
	Loading        bool                  `json:"loading"`
	Error          string                `json:"error,omitempty"`
	CheckedAt      string                `json:"checked_at"`
}

var statisticsGeoSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var statisticsGeoMonth = regexp.MustCompile(`^20[2-9][0-9]-(0[1-9]|1[0-2])$`)

func ValidateStatisticsGeoSelection(in StatisticsGeoSelection) error {
	if in.Action != "install" && in.Action != "rollback" && in.Action != "archive" && in.Action != "restore" || in.AppVersion != StatisticsGeoVersion || !ValidID(in.InstallationID) || !statisticsGeoSHA.MatchString(in.AppManifestSHA) || !statisticsGeoSHA.MatchString(in.DataManifestSHA) || !statisticsGeoMonth.MatchString(in.Release) {
		return errors.New("统计地域任务的动作、应用实例、版本或签名摘要无效")
	}
	return nil
}
func rfcGeoQuery(in StatisticsGeoSelection) string { return StatisticsGeoSelectionQuery(in).Encode() }
func StatisticsGeoSelectionQuery(in StatisticsGeoSelection) url.Values {
	return url.Values{"action": {in.Action}, "app_version": {in.AppVersion}, "app_manifest_sha256": {in.AppManifestSHA}, "installation_id": {in.InstallationID}, "release": {in.Release}, "data_manifest_sha256": {in.DataManifestSHA}}
}
func ParseStatisticsGeoSelectionQuery(q url.Values) (StatisticsGeoSelection, error) {
	var in StatisticsGeoSelection
	fields := []string{"action", "app_version", "app_manifest_sha256", "installation_id", "release", "data_manifest_sha256"}
	if len(q) != len(fields) {
		return in, errors.New("地域查询绑定含未知或缺失字段")
	}
	for _, field := range fields {
		if len(q[field]) != 1 {
			return in, errors.New("地域查询绑定重复或缺失")
		}
	}
	in = StatisticsGeoSelection{q.Get(fields[0]), q.Get(fields[1]), q.Get(fields[2]), q.Get(fields[3]), q.Get(fields[4]), q.Get(fields[5])}
	return in, ValidateStatisticsGeoSelection(in)
}
func DecodeStatisticsGeoSelection(raw []byte) (StatisticsGeoSelection, error) {
	var in StatisticsGeoSelection
	if len(raw) < 1 || len(raw) > 1024 {
		return in, errors.New("统计地域选择超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return in, errors.New("统计地域选择须为对象")
	}
	allowed := map[string]bool{"action": true, "app_version": true, "app_manifest_sha256": true, "installation_id": true, "release": true, "data_manifest_sha256": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return in, errors.New("统计地域选择含重复、未知或非规范字段")
		}
		seen[name] = true
		v, err := d.Token()
		if _, ok := v.(string); err != nil || !ok {
			return in, errors.New("统计地域选择字段须为字符串")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != 6 {
		return in, errors.New("统计地域选择字段不完整")
	}
	if _, err := d.Token(); err != io.EOF {
		return in, errors.New("统计地域选择含多余值")
	}
	if json.Unmarshal(raw, &in) != nil {
		return in, errors.New("统计地域选择解码失败")
	}
	return in, ValidateStatisticsGeoSelection(in)
}
func statisticsGeoReplay(db interface{ QueryRow(string, ...any) *sql.Row }, in StatisticsGeoSelection, key, actor string) (string, bool, error) {
	if ValidateStatisticsGeoSelection(in) != nil || key == "" || len(key) > 128 || strings.TrimSpace(key) != key || !ValidID(actor) {
		return "", false, errors.New("统计地域幂等身份无效")
	}
	if err := statisticsGeoQueueEvidence(db); err != nil {
		return "", false, err
	}
	var id, target, kind, payload, state string
	err := db.QueryRow("SELECT id,target_id,kind,payload,state FROM runtime_jobs WHERE idempotency_key=?", key).Scan(&id, &target, &kind, &payload, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	raw, _ := json.Marshal(in)
	if !ValidID(id) || target != "website-statistics-v2" || kind != "statistics_geodata" || payload != string(raw) || state != "queued" && state != "running" && state != "succeeded" && state != "failed" && state != "needs_attention" {
		return "", false, errors.New("统计地域幂等键已用于其他或损坏任务")
	}
	var count int
	var owner sql.NullString
	err = db.QueryRow("SELECT count(*),min(actor) FROM audit_logs WHERE action='statistics.geodata.queue' AND target=?", id).Scan(&count, &owner)
	if err != nil || count != 1 || !owner.Valid || owner.String != actor {
		return "", false, errors.New("原统计地域任务的用户绑定不能核对")
	}
	return id, true, nil
}
func (s *Store) QueueStatisticsGeo(in StatisticsGeoSelection, key, actor string) (string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = statisticsGeoCurrentAuthority(context.Background(), tx, actor); err != nil {
		return "", err
	}
	if id, found, err := statisticsGeoReplay(tx, in, key, actor); err != nil || found {
		return id, err
	}
	var count int
	if tx.QueryRow("SELECT count(*) FROM runtime_jobs WHERE target_id='website-statistics-v2' AND kind='statistics_geodata' AND state='needs_attention'").Scan(&count) != nil || count != 0 {
		return "", errors.New("原地域任务仍待核对；保留原任务，未创建替代任务")
	}
	if err := tx.QueryRow("SELECT count(*) FROM runtime_jobs j WHERE kind='statistics_geodata' AND NOT EXISTS(SELECT 1 FROM statistics_geodata_job_archives a WHERE a.job_id=j.id)").Scan(&count); err != nil {
		return "", err
	}
	if count >= 128 {
		return "", errors.New("统计地域任务记录达到128份，未清理原证据")
	}
	created, id := Now(), ID()
	raw, _ := json.Marshal(in)
	if _, err = tx.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,'website-statistics-v2','statistics_geodata','queued',?,?,?,?)", id, string(raw), key, created, created); err != nil {
		return "", errors.New("统计应用已有进行中任务，未并行提交")
	}
	if _, err = tx.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.queue',?,'queued',?)", actor, id, created); err != nil {
		return "", err
	}
	return id, tx.Commit()
}
func (a *Server) statisticsGeoRoutes(m *http.ServeMux) {
	a.statisticsGeoRequestRoutes(m)
	a.statisticsGeoArchiveRoutes(m)
	admin := func(w http.ResponseWriter, u identity) bool {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "统计地域数据仅管理员可管理")
			return false
		}
		return true
	}
	m.HandleFunc("GET /api/software/website-statistics-v2/geodata", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var state StatisticsGeoState
		if err := a.Executor.Call(ctx, "GET", "/v1/statistics/geodata", nil, &state); err != nil {
			fail(w, 409, err.Error())
			return
		}
		out := map[string]any{"state": state, "available": nil, "source_error": "", "jobs": []Job{}}
		if state.Installed && state.AppVersion == StatisticsGeoVersion && ValidID(state.InstallationID) {
			in, authority, err := a.AppCatalog.FetchGeoDataEnvelope(ctx, "", time.Now())
			if err != nil {
				out["source_error"] = err.Error()
			} else {
				_ = in
				out["available"] = map[string]any{"app_version": authority.AppVersion(), "app_manifest_sha256": authority.AppSHA256(), "manifest": authority.Data().Manifest(), "manifest_sha256": authority.Data().SHA256()}
			}
		}
		rows, err := a.Store.DB.Query("SELECT id,target_id,kind,state,error,created_at,updated_at FROM runtime_jobs WHERE target_id='website-statistics-v2' AND kind='statistics_geodata' ORDER BY created_at DESC,id DESC LIMIT 16")
		if err != nil {
			fail(w, 503, "统计地域任务记录不可读取")
			return
		}
		defer rows.Close()
		jobs := []Job{}
		for rows.Next() {
			var j Job
			if err = rows.Scan(&j.ID, &j.TargetID, &j.Kind, &j.State, &j.Error, &j.CreatedAt, &j.UpdatedAt); err != nil {
				fail(w, 503, "统计地域任务记录损坏")
				return
			}
			jobs = append(jobs, j)
		}
		if rows.Err() != nil {
			fail(w, 503, "统计地域任务读取不完整")
			return
		}
		out["jobs"] = jobs
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/website-statistics-v2/geodata", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		in, decodeErr := DecodeStatisticsGeoSelection(raw)
		if err != nil || decodeErr != nil {
			fail(w, 400, "统计地域选择无效或超限")
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if id, found, err := statisticsGeoReplay(a.Store.DB, in, key, u.ID); err != nil {
			fail(w, 409, err.Error())
			return
		} else if found {
			send(w, 202, map[string]any{"job_id": id, "replayed": true})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var state StatisticsGeoState
		if err = a.Executor.Call(ctx, "GET", "/v1/statistics/geodata", nil, &state); err != nil || !state.Installed || state.AppVersion != in.AppVersion || state.InstallationID != in.InstallationID {
			fail(w, 409, "统计安装实例已变化或不支持地域功能，请刷新后重试")
			return
		}
		if in.Action == "install" {
			_, authority, err := a.AppCatalog.FetchGeoDataEnvelope(ctx, in.DataManifestSHA, time.Now())
			if err != nil || authority.AppSHA256() != in.AppManifestSHA || authority.Data().Manifest().Release != in.Release {
				fail(w, 409, "地域应用或数据目录已变化，未提交下载")
				return
			}
		} else {
			found := false
			for _, entry := range state.Stored {
				eligible := in.Action == "restore" && entry.Archived || in.Action == "rollback" && !entry.Archived || in.Action == "archive" && !entry.Archived && !entry.Selected && !entry.Previous && !entry.HighWater
				found = found || eligible && entry.AppSHA == in.AppManifestSHA && entry.Release == in.Release && entry.ManifestSHA == in.DataManifestSHA
			}
			if !found {
				fail(w, 409, "选定副本或维护权限不能核对；当前、上一份和防重放锚点不能归档")
				return
			}
		}
		id, err := a.Store.QueueStatisticsGeo(in, key, u.ID)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]any{"job_id": id, "replayed": false})
	}))
}

// Observe one immutable root job ID. A lost POST reply never causes another
// submission, dataset download or operation ID. Root work has an external unit
// deadline; Core's observation deadline is not installation success.
func runStatisticsGeoJob(parent context.Context, s *Store, e *ExecutorClient, j Job, repo *appcatalog.Client) {
	ctx, cancel := context.WithTimeout(parent, 7*time.Minute)
	defer cancel()
	steps := []Step{}
	finish := func(detail string, uncertain bool) {
		if parent.Err() == nil {
			_ = s.finishRuntime(j, detail, steps, uncertain)
		}
	}
	in, err := DecodeStatisticsGeoSelection([]byte(j.Payload))
	if err != nil || j.TargetID != "website-statistics-v2" || !ValidID(j.ID) || j.Kind != "statistics_geodata" || repo == nil {
		finish("统计地域任务身份无效", false)
		return
	}
	observeOnly, err := s.statisticsGeoDispatchBoundary(ctx, j, false)
	if err != nil {
		finish(err.Error(), true)
		return
	}
	var envelope appcatalog.GeoDataEnvelope
	if !observeOnly && in.Action == "install" {
		var a appcatalog.GeoDataAuthority
		envelope, a, err = repo.FetchGeoDataEnvelope(ctx, in.DataManifestSHA, time.Now())
		if err != nil || a.AppVersion() != in.AppVersion || a.AppSHA256() != in.AppManifestSHA || a.Data().Manifest().Release != in.Release {
			finish("地域应用或数据交付与原任务不符", false)
			return
		}
	}
	query := rfcGeoQuery(in)
	endpoint := "/v1/statistics/geodata/jobs/" + j.ID
	var out StatisticsGeoOperation
	if !observeOnly {
		observeOnly, err = s.statisticsGeoDispatchBoundary(ctx, j, true)
		if err != nil {
			finish(err.Error(), true)
			return
		}
		if !observeOnly {
			submit, stop := context.WithTimeout(ctx, 20*time.Second)
			var payload any = envelope
			if in.Action != "install" {
				payload = map[string]any{}
			}
			err = e.Call(submit, "POST", endpoint+"?"+query, payload, &out)
			stop()
			if err != nil {
				out = StatisticsGeoOperation{}
				steps = append(steps, Step{Time: Now(), Message: "提交回执未收到，只观察原任务，不重发或重新下载"})
			}
		}
	}
	for {
		if out.JobID != "" {
			if out.JobID != j.ID || out.Selection != in || len(out.Error) > 1024 || len(out.Steps) > 16 {
				finish("统计地域回执绑定无效", true)
				return
			}
			switch out.State {
			case "succeeded":
				if out.Error != "" {
					finish("地域完成记录仍有未解决错误", true)
				} else {
					steps = append(steps, out.Steps...)
					finish("", false)
				}
				return
			case "failed":
				if out.Error == "" {
					finish("地域失败回执缺少原因，未宣称完成", true)
				} else {
					finish(out.Error, false)
				}
				return
			case "needs-attention":
				finish(out.Error, true)
				return
			case "queued", "running":
			default:
				finish("地域任务状态无法核对", true)
				return
			}
		}
		select {
		case <-ctx.Done():
			finish("地域原任务观察达到上限，未宣称成功；请核对原任务", true)
			return
		case <-time.After(2 * time.Second):
		}
		observe, stop := context.WithTimeout(ctx, 15*time.Second)
		var next StatisticsGeoOperation
		err = e.Call(observe, "GET", endpoint, nil, &next)
		stop()
		if err != nil {
			out = StatisticsGeoOperation{}
			if temporaryRuleFeedObservation(err) {
				continue
			}
			finish("地域原任务不能核对："+err.Error(), true)
			return
		}
		if next.JobID == "" {
			finish("地域回执缺少原任务标识", true)
			return
		}
		out = next
	}
}
