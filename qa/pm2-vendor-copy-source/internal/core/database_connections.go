package core

import (
	"context"
	"net/http"
	"time"
)

type DatabaseConnection struct {
	ServerID string `json:"server_id"`
	Clients  int    `json:"clients"`
}

func (a *Server) databaseConnectionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/databases/connections/history", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		points, err := a.Store.DatabaseConnectionHistory(time.Now())
		if err != nil {
			fail(w, 500, "读取数据库连接历史失败")
			return
		}
		send(w, 200, map[string]any{"samples": points, "window_seconds": 86400})
	}))
	m.HandleFunc("GET /api/databases/connections", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		servers, err := a.Store.DatabaseServers()
		if err != nil {
			fail(w, 500, "读取数据库实例失败")
			return
		}
		ids := make([]string, 0, len(servers))
		for _, server := range servers {
			switch server.Status {
			case "running":
				ids = append(ids, server.ID)
			case "stopped":
			default:
				fail(w, 503, "数据库实例状态待核对，连接数暂不可读取")
				return
			}
		}
		if len(ids) > 20 {
			fail(w, 503, "运行中的数据库实例超过连接统计上限")
			return
		}
		if len(ids) == 0 {
			send(w, 200, map[string]any{"sampled_at": time.Now().UTC().Format(time.RFC3339), "connections": []DatabaseConnection{}})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		var result struct {
			Connections []DatabaseConnection `json:"connections"`
		}
		if err := a.Executor.Call(ctx, http.MethodPost, "/v1/databases/connections", map[string]any{"server_ids": ids}, &result); err != nil {
			fail(w, 503, "数据库连接数暂不可读取")
			return
		}
		wanted := map[string]bool{}
		for _, id := range ids {
			wanted[id] = true
		}
		if len(result.Connections) != len(ids) {
			fail(w, 503, "部分数据库实例连接数暂不可读取")
			return
		}
		for _, item := range result.Connections {
			if !wanted[item.ServerID] || item.Clients < 0 || item.Clients > 1000000 {
				fail(w, 503, "数据库连接数结果无效")
				return
			}
			delete(wanted, item.ServerID)
		}
		send(w, 200, map[string]any{"sampled_at": time.Now().UTC().Format(time.RFC3339), "connections": result.Connections})
	}))
}
