package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

const dailyReportRecordBytes = 4 << 20

// Corrupt source material is distinct from database, cancellation and IO
// failures. Only this class (or a genuinely absent row) may be quarantined.
var errDailyReportInvalid = errors.New("日报原记录无法核对")

func (s *Store) dailyTrafficSiteIDs(ctx context.Context) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM sites ORDER BY id LIMIT 129`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !ValidID(id) || len(ids) >= 128 {
			return nil, errors.New("网站身份或数量超出有界流量采集范围")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

type dailyReportQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Bound UTF-8 bytes in SQLite before returning text; never allocate an
// unbounded stored string before checking the application limit.
func readDailyReportRecord(ctx context.Context, query dailyReportQuery, day string) (string, map[string]any, error) {
	statement := `SELECT CASE WHEN length(CAST(day AS BLOB))=10 THEN day ELSE NULL END,length(CAST(report AS BLOB)),CASE WHEN length(CAST(report AS BLOB)) BETWEEN 1 AND ? THEN report ELSE NULL END FROM app_daily_reports`
	args := []any{dailyReportRecordBytes}
	if day != "" {
		if !validDailyReportDay(day) {
			return "", nil, errors.Join(errDailyReportInvalid, errors.New("请选择有效的报告日期 YYYY-MM-DD"))
		}
		statement += ` WHERE day=?`
		args = append(args, day)
	}
	statement += ` ORDER BY day DESC LIMIT 1`
	var actual sql.NullString
	var size int64
	var raw sql.NullString
	if err := query.QueryRowContext(ctx, statement, args...).Scan(&actual, &size, &raw); err != nil {
		return "", nil, err
	}
	if !actual.Valid || !validDailyReportDay(actual.String) || size < 1 || size > dailyReportRecordBytes || !raw.Valid || int64(len(raw.String)) != size {
		return "", nil, errors.Join(errDailyReportInvalid, errors.New("日报身份或容量无法核对；保留原记录，未按无日报返回"))
	}
	report, err := decodeDailyReportRecord([]byte(raw.String))
	if err != nil {
		return "", nil, errors.Join(errDailyReportInvalid, err)
	}
	return actual.String, report, nil
}
func validDailyReportDay(day string) bool {
	parsed, err := time.Parse("2006-01-02", day)
	return err == nil && parsed.Format("2006-01-02") == day
}

func outboundDailyReportSummary(day string, record map[string]any) (OutboundDailySummary, error) {
	var summary OutboundDailySummary
	if !validDailyReportDay(day) {
		return summary, errors.New("日报推送日期无效")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return summary, err
	}
	validated, err := decodeDailyReportRecord(raw)
	if err != nil {
		return summary, err
	}
	summary.Day = day
	summary.CountAvailable = map[string]bool{}
	for _, field := range []struct {
		key    string
		target *int
	}{
		{"sites", &summary.Sites}, {"running_sites", &summary.RunningSites},
		{"failed_site_jobs", &summary.FailedSiteJobs}, {"failed_runtime_jobs", &summary.FailedRuntimeJobs},
		{"audit_events_24h", &summary.AuditEvents}, {"certificates_due_14_days", &summary.CertificatesDue},
	} {
		value, exists := validated[field.key]
		summary.CountAvailable[field.key] = exists
		if exists {
			*field.target = int(value.(float64))
		}
	}
	// Decode only canonical allowlisted names; JSON's case-insensitive struct
	// matching must not promote an unrelated legacy field to a verified metric.
	if resources, ok := validated["resources"].(map[string]any); ok {
		for _, field := range []struct {
			key, available string
			target         **float64
		}{
			{"cpu_percent", "cpu_available", &summary.Resources.CPU},
			{"memory_percent", "memory_available", &summary.Resources.Memory},
			{"disk_percent", "disk_percent_available", &summary.Resources.Disk},
		} {
			if resources[field.available] == false {
				continue
			}
			if value, ok := resources[field.key].(float64); ok {
				if field.key == "cpu_percent" && value == 0 && resources[field.available] != true {
					continue // Legacy first-sample default is not an observed idle interval.
				}
				n := value
				*field.target = &n
			}
		}
	}
	return summary, nil
}

// New payloads omit missing legacy counters instead of synthesizing zeros.
// Old queued payloads without availability flags retain positive numbers, but
// their zero defaults are unknown, not certified observed zero measurements.
func (r OutboundDailySummary) MarshalJSON() ([]byte, error) {
	value := map[string]any{"day": r.Day, "resources": r.Resources}
	for _, item := range []struct {
		key   string
		value int
	}{{"sites", r.Sites}, {"running_sites", r.RunningSites}, {"failed_site_jobs", r.FailedSiteJobs}, {"failed_runtime_jobs", r.FailedRuntimeJobs}, {"audit_events_24h", r.AuditEvents}, {"certificates_due_14_days", r.CertificatesDue}} {
		if r.CountAvailable != nil && r.CountAvailable[item.key] || r.CountAvailable == nil && item.value != 0 {
			value[item.key] = item.value
		}
	}
	if r.CountAvailable != nil {
		value["count_available"] = r.CountAvailable
	}
	return json.Marshal(value)
}

// Partial legacy objects stay readable. Missing counters are not invented as
// zeros; duplicate/escaped/case-equivalent keys at every level are refused.
func decodeDailyReportRecord(raw []byte) (map[string]any, error) {
	if len(raw) < 2 || len(raw) > dailyReportRecordBytes || !utf8.Valid(raw) {
		return nil, errors.New("日报容量或文本编码无效；未修改记录")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 16 || nodes > 100000 {
			return errors.New("日报结构超过安全容量")
		}
		token, err := d.Token()
		if err != nil {
			return errors.New("日报 JSON 内容无法核对")
		}
		if delimiter, ok := token.(json.Delim); ok {
			if depth == 0 && delimiter != '{' {
				return errors.New("日报须为对象，未当作正常报告")
			}
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					token, err := d.Token()
					key, ok := token.(string)
					if err != nil || !ok || seen[strings.ToLower(key)] {
						return errors.New("日报有重复或大小写冲突字段")
					}
					seen[strings.ToLower(key)] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("日报结构无效")
			}
			end, err := d.Token()
			if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return errors.New("日报结构不完整")
			}
		} else if depth == 0 {
			return errors.New("日报须为对象")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("日报有额外 JSON 内容")
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil || report == nil {
		return nil, errors.New("日报内容无法解码")
	}
	for _, key := range []string{"sites", "running_sites", "failed_site_jobs", "failed_runtime_jobs", "audit_events_24h", "certificates_due_14_days"} {
		if value, exists := report[key]; exists {
			n, ok := value.(float64)
			if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1000000000 || n != math.Trunc(n) {
				return nil, errors.New("日报计数无法核对；未当作正常零值")
			}
		}
	}
	if value, exists := report["resources"]; exists && value != nil {
		resources, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("日报资源统计不是可核对的对象")
		}
		for _, key := range []string{"cpu_percent", "memory_percent", "disk_percent"} {
			if value, exists := resources[key]; exists && value != nil {
				n, ok := value.(float64)
				if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 100 {
					return nil, errors.New("日报资源统计无法核对；未按正常百分比读取")
				}
			}
		}
		// disk_available is the executor's existing free-byte measurement, not
		// an availability flag. Keep that public contract unchanged.
		for _, key := range []string{"cpu_available", "memory_available", "disk_percent_available"} {
			if _, exists := resources[key]; exists {
				if _, ok := resources[key].(bool); !ok {
					return nil, errors.New("日报资源可用性标记无效")
				}
			}
		}
	}
	if value, exists := report["created_at"]; exists {
		stamp, ok := value.(string)
		if !ok {
			return nil, errors.New("日报生成时间无效")
		}
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			return nil, errors.New("日报生成时间无效")
		}
	}
	return report, nil
}

// Snapshot and deduplicated outbound source event commit together. A failed
// event insertion rolls the report back instead of losing its automatic push.
func (s *Store) saveDailyReportRecord(ctx context.Context, day string, report map[string]any) error {
	if !validDailyReportDay(day) {
		return errors.New("日报保存日期无效")
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if _, err = decodeDailyReportRecord(raw); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, _, err := readDailyReportRecord(ctx, tx, day); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.New("原日期日报无法核对，未覆盖或自动修复")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO app_daily_reports(day,report,created_at) VALUES(?,?,?) ON CONFLICT(day) DO UPDATE SET report=excluded.report,created_at=excluded.created_at`, day, string(raw), Now()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at) VALUES(?,'daily','每日运维报告','今日报告已生成','info','daily-report',?,?)`, ID(), day, time.Now().Unix()); err != nil {
		return errors.New("日报推送来源保存失败；报告事务未提交")
	}
	return tx.Commit()
}
