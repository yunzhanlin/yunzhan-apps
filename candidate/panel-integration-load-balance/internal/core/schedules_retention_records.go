package core

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type ScheduleRetentionRecord struct {
	Engine       string `json:"engine"`
	ArtifactID   string `json:"artifact_id"`
	ScheduleID   string `json:"schedule_id"`
	ScheduleName string `json:"schedule_name"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
	State        string `json:"state"`
	Attempts     int64  `json:"attempts"`
	LastError    string `json:"last_error"`
	CreatedAt    string `json:"created_at"`
	CompletedAt  string `json:"completed_at"`
	Status       string `json:"status"`
}

type ScheduleRetentionRecords struct {
	Items    []ScheduleRetentionRecord `json:"items"`
	Counts   map[string]int64          `json:"counts"`
	Total    int64                     `json:"total"`
	Limit    int                       `json:"limit"`
	Offset   int                       `json:"offset"`
	HasMore  bool                      `json:"has_more"`
	ReadOnly bool                      `json:"read_only"`
}

func retentionRecordsSQL() string {
	parts := make([]string, 0, 3)
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		table, _ := retentionTable(engine)
		ready, _ := readyRetentionPredicate(engine)
		parts = append(parts, `SELECT '`+engine+`' engine,artifact_id,schedule_id,schedule_name,bytes,sha256,state,attempts,last_error,created_at,completed_at,
CASE WHEN state='completed' THEN 'completed' WHEN attempts>0 OR last_error!='' THEN 'needs_attention' WHEN `+ready+` THEN 'ready' ELSE 'held' END status FROM `+table)
	}
	return strings.Join(parts, ` UNION ALL `)
}

func (s *Store) ScheduleRetentionRecords(ctx context.Context, limit, offset int) (ScheduleRetentionRecords, error) {
	out := ScheduleRetentionRecords{Items: []ScheduleRetentionRecord{}, Counts: map[string]int64{"needs_attention": 0, "ready": 0, "held": 0, "completed": 0}, Limit: limit, Offset: offset, ReadOnly: true}
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return out, errors.New("清理记录分页无效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	query := retentionRecordsSQL()
	counts, err := tx.QueryContext(ctx, `SELECT status,count(*) FROM (`+query+`) GROUP BY status`)
	if err != nil {
		return out, err
	}
	for counts.Next() {
		var status string
		var count int64
		if err = counts.Scan(&status, &count); err != nil {
			counts.Close()
			return out, err
		}
		if _, ok := out.Counts[status]; !ok {
			counts.Close()
			return out, errors.New("清理记录状态无效")
		}
		out.Counts[status] = count
		out.Total += count
	}
	err = counts.Err()
	counts.Close()
	if err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT * FROM (`+query+`) ORDER BY CASE status WHEN 'needs_attention' THEN 0 WHEN 'ready' THEN 1 WHEN 'held' THEN 2 ELSE 3 END,created_at DESC,engine,artifact_id LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v ScheduleRetentionRecord
		if err = rows.Scan(&v.Engine, &v.ArtifactID, &v.ScheduleID, &v.ScheduleName, &v.Bytes, &v.SHA256, &v.State, &v.Attempts, &v.LastError, &v.CreatedAt, &v.CompletedAt, &v.Status); err != nil {
			rows.Close()
			return out, err
		}
		out.Items = append(out.Items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	out.HasMore = int64(offset+len(out.Items)) < out.Total
	return out, tx.Commit()
}

func (a *Server) scheduleRetentionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/schedules/retention", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		query := r.URL.Query()
		limit, offset := 20, 0
		for name, values := range query {
			if (name != "limit" && name != "offset") || len(values) != 1 {
				fail(w, 400, "清理记录分页无效")
				return
			}
			n, err := strconv.Atoi(values[0])
			if err != nil {
				fail(w, 400, "清理记录分页无效")
				return
			}
			if name == "limit" {
				limit = n
			} else {
				offset = n
			}
		}
		if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
			fail(w, 400, "清理记录分页无效")
			return
		}
		out, err := a.Store.ScheduleRetentionRecords(r.Context(), limit, offset)
		if err != nil {
			fail(w, 500, "读取备份清理记录失败")
			return
		}
		send(w, 200, out)
	}))
}
