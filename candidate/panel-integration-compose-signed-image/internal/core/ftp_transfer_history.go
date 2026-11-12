package core

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var ftpHistoryUsername = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)

type FTPTransferQuery struct {
	Minutes   int
	End       time.Time
	Limit     int
	Direction string
	Username  string
	SiteID    string
}

func ParseFTPTransferQuery(values url.Values) (FTPTransferQuery, error) {
	query := FTPTransferQuery{Minutes: 60, Limit: 100}
	for key, values := range values {
		if len(values) != 1 {
			return query, errors.New("传输日志筛选条件重复")
		}
		value := values[0]
		switch key {
		case "minutes":
			switch value {
			case "15", "60", "1440", "10080":
				query.Minutes, _ = strconv.Atoi(value)
			default:
				return query, errors.New("请选择 15 分钟、1 小时、24 小时或 7 天")
			}
		case "end":
			if value != "" {
				end, err := time.Parse(time.RFC3339Nano, value)
				if err != nil || end.Unix() < 0 {
					return query, errors.New("传输日志结束时间无效")
				}
				query.End = end.UTC()
			}
		case "limit":
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 250 || strconv.Itoa(limit) != value {
				return query, errors.New("传输日志每次最多查询 250 条")
			}
			query.Limit = limit
		case "direction":
			if value != "" && value != "upload" && value != "download" {
				return query, errors.New("传输方向无效")
			}
			query.Direction = value
		case "username":
			if value != "" && !ftpHistoryUsername.MatchString(value) {
				return query, errors.New("FTP 用户名格式无效")
			}
			query.Username = value
		case "site_id":
			if value != "" && !ValidID(value) {
				return query, errors.New("站点标识无效")
			}
			query.SiteID = value
		default:
			return query, errors.New("传输日志筛选条件无效")
		}
	}
	return query, nil
}

type FTPTransferRecord struct {
	Time         time.Time `json:"time"`
	SiteID       string    `json:"site_id"`
	Username     string    `json:"username"`
	ClientIP     string    `json:"client_ip"`
	Direction    string    `json:"direction"`
	Path         string    `json:"path"`
	Bytes        uint64    `json:"bytes,string"`
	KiBPerSecond float64   `json:"kib_per_second"`
}

type FTPTransferHistory struct {
	From        time.Time           `json:"from"`
	To          time.Time           `json:"to"`
	Events      []FTPTransferRecord `json:"events"`
	SourceLimit int                 `json:"source_limit"`
	HasMore     bool                `json:"has_more"`
}

func (a *Server) ftpTransferHistoryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/pure-ftpd/transfers", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			fail(w, http.StatusBadRequest, "传输日志筛选条件无效")
			return
		}
		if _, err = ParseFTPTransferQuery(values); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		ctx := r.Context()
		var report FTPTransferHistory
		if err = a.Executor.Call(ctx, http.MethodGet, "/v1/app-modules/pure-ftpd/transfers?"+values.Encode(), nil, &report); err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		send(w, http.StatusOK, report)
	}))
}
