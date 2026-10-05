package core

import (
	"context"
	"net/http"
	"time"
)

type DatabaseMetricTarget struct {
	ServerID string   `json:"server_id"`
	Names    []string `json:"names"`
}

type DatabaseMetric struct {
	ServerID string `json:"server_id"`
	Name     string `json:"name"`
	Bytes    int64  `json:"bytes"`
	Charset  string `json:"charset"`
}

func (a *Server) databaseMetricRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/databases/metrics", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		databases, err := a.Store.Databases()
		if err != nil {
			fail(w, 500, "读取数据库失败")
			return
		}
		groups := map[string][]string{}
		for _, db := range databases {
			if db.Status != "quarantined" {
				groups[db.ServerID] = append(groups[db.ServerID], db.Name)
			}
		}
		targets := []DatabaseMetricTarget{}
		for id, names := range groups {
			targets = append(targets, DatabaseMetricTarget{ServerID: id, Names: names})
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var result struct {
			Metrics []DatabaseMetric `json:"metrics"`
		}
		if err = a.Executor.Call(ctx, http.MethodPost, "/v1/databases/metrics", map[string]any{"targets": targets}, &result); err != nil {
			fail(w, 503, "数据库容量暂不可读取")
			return
		}
		if result.Metrics == nil {
			result.Metrics = []DatabaseMetric{}
		}
		send(w, 200, result)
	}))
}
