package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const StatisticsGeoActiveJobsMax = 128
const StatisticsGeoArchivedJobsMax = 512

// Native leaves:3 MiB original envelope,4 KiB request,4 KiB start,
// 32 KiB terminal and an empty lock. Do not reject a valid large original job.
const StatisticsGeoJobEvidenceMaxBytes = 3<<20 + 40<<10

type StatisticsGeoJobRecord struct {
	JobID    string `json:"job_id"`
	State    string `json:"state"`
	SHA      string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Archived bool   `json:"archived"`
}
type StatisticsGeoJobInventory struct {
	Entries    []StatisticsGeoJobRecord `json:"entries"`
	ActiveMax  int                      `json:"active_max"`
	ArchiveMax int                      `json:"archive_max"`
	ReadOnly   bool                     `json:"read_only"`
}
type StatisticsGeoArchiveInput struct {
	JobID   string `json:"job_id"`
	SHA     string `json:"expected_sha256"`
	Confirm string `json:"confirm"`
}
type StatisticsGeoArchiveResult struct {
	Record   StatisticsGeoJobRecord `json:"record"`
	Replayed bool                   `json:"replayed"`
}

func ValidateStatisticsGeoArchive(in StatisticsGeoArchiveInput) error {
	if !ValidID(in.JobID) || !statisticsGeoSHA.MatchString(in.SHA) || in.Confirm != "ARCHIVE GEODATA JOB "+in.JobID {
		return errors.New("归档须绑定原任务标识、完整摘要和明确确认；不接受路径或删除动作")
	}
	return nil
}
func DecodeStatisticsGeoArchive(raw []byte) (StatisticsGeoArchiveInput, error) {
	var in StatisticsGeoArchiveInput
	if len(raw) > 1024 || !wafInventoryJSONShape(raw, []string{"job_id", "expected_sha256", "confirm"}) || json.Unmarshal(raw, &in) != nil {
		return in, errors.New("地域任务归档字段重复、未知、缺失或超限")
	}
	return in, ValidateStatisticsGeoArchive(in)
}
func validStatisticsGeoJobRecord(row StatisticsGeoJobRecord) bool {
	terminal := row.State == "succeeded" || row.State == "failed"
	return ValidID(row.JobID) && row.Bytes > 0 && row.Bytes <= StatisticsGeoJobEvidenceMaxBytes && (terminal && statisticsGeoSHA.MatchString(row.SHA) || !row.Archived && row.State == "pending" && row.SHA == "")
}
func DecodeStatisticsGeoJobInventory(raw []byte) (StatisticsGeoJobInventory, error) {
	var out StatisticsGeoJobInventory
	bad := errors.New("地域任务完整库存不能核对；未显示部分或空成功列表")
	if len(raw) > 256<<10 || !wafInventoryJSONShape(raw, []string{"entries", "active_max", "archive_max", "read_only"}) || json.Unmarshal(raw, &out) != nil || out.Entries == nil || out.ActiveMax != StatisticsGeoActiveJobsMax || out.ArchiveMax != StatisticsGeoArchivedJobsMax || !out.ReadOnly || len(out.Entries) > 640 {
		return out, bad
	}
	var wire struct {
		Entries []json.RawMessage `json:"entries"`
	}
	_ = json.Unmarshal(raw, &wire)
	active, archived, previous := 0, 0, ""
	for i, row := range out.Entries {
		if !validStatisticsGeoJobRecord(row) || row.JobID <= previous || !wafInventoryJSONShape(wire.Entries[i], []string{"job_id", "state", "sha256", "bytes", "archived"}) {
			return StatisticsGeoJobInventory{}, bad
		}
		previous = row.JobID
		if row.Archived {
			archived++
		} else {
			active++
		}
	}
	if active > out.ActiveMax || archived > out.ArchiveMax {
		return StatisticsGeoJobInventory{}, bad
	}
	return out, nil
}
func DecodeStatisticsGeoArchiveResult(raw []byte, in StatisticsGeoArchiveInput) (StatisticsGeoArchiveResult, error) {
	var out StatisticsGeoArchiveResult
	bad := errors.New("归档交接回执不能核对；保留原任务和摘要，不宣称未移动")
	var shape struct {
		Record json.RawMessage `json:"record"`
	}
	if ValidateStatisticsGeoArchive(in) != nil || len(raw) > 4096 || !wafInventoryJSONShape(raw, []string{"record", "replayed"}) || json.Unmarshal(raw, &out) != nil || json.Unmarshal(raw, &shape) != nil || !wafInventoryJSONShape(shape.Record, []string{"job_id", "state", "sha256", "bytes", "archived"}) || !validStatisticsGeoJobRecord(out.Record) || !out.Record.Archived || out.Record.JobID != in.JobID || out.Record.SHA != in.SHA {
		return StatisticsGeoArchiveResult{}, bad
	}
	return out, nil
}
func statisticsGeoArchiveCoreJob(db interface{ QueryRow(string, ...any) *sql.Row }, id string) (string, error) {
	var target, kind, state string
	if !ValidID(id) || db.QueryRow("SELECT target_id,kind,state FROM runtime_jobs WHERE id=?", id).Scan(&target, &kind, &state) != nil || target != "website-statistics-v2" || kind != "statistics_geodata" || state != "succeeded" && state != "failed" {
		return "", errors.New("原地域任务不是可核对的成功/失败终态；运行中或待处理证据不可归档")
	}
	return state, nil
}
func (s *Store) finishStatisticsGeoArchive(ctx context.Context, actor string, in StatisticsGeoArchiveInput, out StatisticsGeoArchiveResult, requestAudit int64) error {
	if !ValidID(actor) || ValidateStatisticsGeoArchive(in) != nil || !validStatisticsGeoJobRecord(out.Record) || !out.Record.Archived || out.Record.JobID != in.JobID || out.Record.SHA != in.SHA {
		return errors.New("归档审计身份不可核对")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := statisticsGeoArchiveCoreJob(tx, in.JobID)
	if err != nil || state != out.Record.State {
		return errors.New("原地域任务与执行器终态不同；未释放活动容量")
	}
	var auditActor, auditTarget, auditAction, auditSHA string
	if tx.QueryRow("SELECT actor,target,action,result FROM audit_logs WHERE id=?", requestAudit).Scan(&auditActor, &auditTarget, &auditAction, &auditSHA) != nil || auditActor != actor || auditTarget != in.JobID || auditAction != "statistics.geodata.archive.request" || auditSHA != in.SHA {
		return errors.New("原归档请求审计不同")
	}
	var sha string
	err = tx.QueryRow("SELECT sha256 FROM statistics_geodata_job_archives WHERE job_id=?", in.JobID).Scan(&sha)
	if err == nil && sha != in.SHA {
		return errors.New("原归档摘要改变；未覆盖")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if tx.QueryRow("SELECT count(*) FROM statistics_geodata_job_archives").Scan(&count) != nil || count >= StatisticsGeoArchivedJobsMax {
			return errors.New("Core 原归档标记已满，未释放更多活动容量")
		}
		_, err = tx.Exec("INSERT INTO statistics_geodata_job_archives(job_id,sha256,actor_id,created_at) VALUES(?,?,?,?)", in.JobID, in.SHA, actor, Now())
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.archive.complete',?,?,?)", actor, in.JobID, in.SHA, Now())
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (a *Server) statisticsGeoArchiveRoutes(m *http.ServeMux) {
	admin := func(w http.ResponseWriter, u identity) bool {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "地域任务证据仅管理员可管理")
			return false
		}
		return true
	}
	endpoint := "/api/software/website-statistics-v2/geodata-job-records"
	m.HandleFunc("GET "+endpoint, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(w, u) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "库存不接受查询路径或过滤条件")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var raw json.RawMessage
		if err := a.Executor.Call(ctx, "GET", "/v1/statistics/geodata-job-records", nil, &raw); err != nil {
			fail(w, 409, err.Error())
			return
		}
		out, err := DecodeStatisticsGeoJobInventory(raw)
		if err != nil {
			fail(w, 503, err.Error())
			return
		}
		marked := []string{}
		rootRows := map[string]StatisticsGeoJobRecord{}
		for _, row := range out.Entries {
			rootRows[row.JobID] = row
		}
		rows, err := a.Store.DB.Query("SELECT job_id,sha256 FROM statistics_geodata_job_archives ORDER BY job_id LIMIT 513")
		if err != nil {
			fail(w, 503, "原归档标记不可读取")
			return
		}
		ok := true
		for rows.Next() {
			var id, sha string
			if rows.Scan(&id, &sha) != nil {
				ok = false
				break
			}
			row, found := rootRows[id]
			if !found || !row.Archived || row.SHA != sha {
				ok = false
				break
			}
			marked = append(marked, id)
		}
		if rows.Err() != nil {
			ok = false
		}
		rows.Close()
		if !ok || len(marked) > StatisticsGeoArchivedJobsMax {
			fail(w, 503, "Core 与全部原归档库存不同；未返回部分成功")
			return
		}
		send(w, 200, map[string]any{"inventory": out, "committed": marked})
	}))
	m.HandleFunc("POST "+endpoint+"/archive", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(w, u) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "归档不接受查询字段")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		in, decodeErr := DecodeStatisticsGeoArchive(raw)
		if err != nil || decodeErr != nil {
			fail(w, 400, "原归档请求字段无效")
			return
		}
		state, err := statisticsGeoArchiveCoreJob(a.Store.DB, in.JobID)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		result, err := a.Store.DB.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.archive.request',?,?,?)", u.ID, in.JobID, in.SHA, Now())
		if err != nil {
			fail(w, 503, "归档请求审计未保存；未派发")
			return
		}
		audit, err := result.LastInsertId()
		if err != nil {
			fail(w, 503, "归档请求审计标识不可核对；未派发")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var response json.RawMessage
		if err = a.Executor.Call(ctx, "POST", "/v1/statistics/geodata-job-records/archive", in, &response); err != nil {
			fail(w, 503, "归档结果未确认；请核对库存并使用原任务和摘要，不自动重发")
			return
		}
		out, err := DecodeStatisticsGeoArchiveResult(response, in)
		if err != nil || out.Record.State != state {
			fail(w, 503, "归档原回执或终态不同；未释放活动容量")
			return
		}
		if err = a.Store.finishStatisticsGeoArchive(ctx, u.ID, in, out, audit); err != nil {
			fail(w, 503, "原证据可能已归档，但 Core 提交未核对；请用同一任务和摘要完成核对")
			return
		}
		send(w, 200, out)
	}))
}
