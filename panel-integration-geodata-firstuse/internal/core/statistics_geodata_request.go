package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

var errStatisticsGeoRequest = errors.New("原地域请求或账户审计不能核对；保留原编号与证据，未创建替代任务")

// An orphan/duplicated queue audit is retained uncertainty, not permission to
// enqueue a replacement under the old or a fresh key. Archived jobs retain
// their immutable Core row too; there is no archive/deletion exemption.
func statisticsGeoQueueEvidence(db interface{ QueryRow(string, ...any) *sql.Row }) error {
	var bad int
	if db.QueryRow(`SELECT count(*) FROM (
 SELECT target,count(*) AS n,min(result) AS result FROM audit_logs
 WHERE action='statistics.geodata.queue' GROUP BY target
) a LEFT JOIN runtime_jobs j ON j.id=a.target
WHERE a.n<>1 OR coalesce(a.result,'')<>'queued' OR j.id IS NULL OR j.kind<>'statistics_geodata' OR j.target_id<>'website-statistics-v2'`).Scan(&bad) != nil || bad != 0 {
		return errStatisticsGeoRequest
	}
	return nil
}

type statisticsGeoRequestOutcome struct {
	RequestID  string                  `json:"request_id"`
	JobID      string                  `json:"job_id"`
	Selection  *StatisticsGeoSelection `json:"selection,omitempty"`
	State      string                  `json:"state"`
	StateKnown bool                    `json:"state_known"`
	Detail     string                  `json:"detail"`
}

// Read one original actor-bound SQL request only. No catalog fetch, executor
// call, reservation, reconciliation, queue, download or native POST.
func (s *Store) statisticsGeoRequestState(ctx context.Context, key, actor string) (statisticsGeoRequestOutcome, error) {
	out := statisticsGeoRequestOutcome{RequestID: key, State: "unknown", Detail: "尚未找到对应原请求；不能据此认定未提交，保留原编号"}
	if !ValidID(key) || !ValidID(actor) {
		return out, errStatisticsGeoRequest
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, errStatisticsGeoRequest
	}
	defer tx.Rollback()
	if statisticsGeoCurrentAuthority(ctx, tx, actor) != nil || statisticsGeoQueueEvidence(tx) != nil {
		return out, errStatisticsGeoRequest
	}
	var payload string
	err = tx.QueryRowContext(ctx, `SELECT payload FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, errStatisticsGeoRequest
	}
	in, err := DecodeStatisticsGeoSelection([]byte(payload))
	if err != nil {
		return out, errStatisticsGeoRequest
	}
	id, found, err := statisticsGeoReplay(tx, in, key, actor)
	if err != nil || !found {
		return out, errStatisticsGeoRequest
	}
	var state string
	if tx.QueryRowContext(ctx, `SELECT state FROM runtime_jobs WHERE id=? AND idempotency_key=?`, id, key).Scan(&state) != nil {
		return out, errStatisticsGeoRequest
	}
	out.JobID, out.Selection, out.State, out.StateKnown, out.Detail = id, &in, state, true, "已只读核对原账户、原编号、原选项及 Core 任务记录；不重新提交执行"
	return out, nil
}

func (a *Server) statisticsGeoRequestRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/website-statistics-v2/geodata/requests/{key}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !ValidID(r.PathValue("key")) || r.URL.RawQuery != "" {
			fail(w, 400, "原地域请求编号无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		out, err := a.Store.statisticsGeoRequestState(ctx, r.PathValue("key"), actor.ID)
		if err != nil {
			fail(w, 409, errStatisticsGeoRequest.Error())
			return
		}
		send(w, 200, out)
	}))
}
