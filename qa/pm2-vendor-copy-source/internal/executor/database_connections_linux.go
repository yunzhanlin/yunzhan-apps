//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Service) databaseConnectionRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/databases/connections", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ServerIDs []string `json:"server_ids"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if len(in.ServerIDs) > 20 {
			respond(w, 400, map[string]string{"error": "实例数量超出统计上限"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		out := make([]core.DatabaseConnection, 0, len(in.ServerIDs))
		seen := map[string]bool{}
		for _, id := range in.ServerIDs {
			if !core.ValidID(id) || seen[id] {
				respond(w, 400, map[string]string{"error": "数据库实例标识无效"})
				return
			}
			seen[id] = true
			manifest, err := readMySQL(id)
			if err != nil || !manifest.Ready {
				continue
			}
			state, _ := RunCommand(ctx, "/usr/bin/systemctl", "is-active", mysqlUnit(id))
			if strings.TrimSpace(state) != "active" {
				continue
			}
			raw, err := mysqlQuery(ctx, manifest.Server, "SHOW GLOBAL STATUS LIKE 'Threads_connected';\n")
			if err != nil {
				continue
			}
			count, err := parseMySQLConnections(raw)
			if err != nil {
				continue
			}
			out = append(out, core.DatabaseConnection{ServerID: id, Clients: count})
		}
		respond(w, 200, map[string]any{"connections": out})
	})
}

func parseMySQLConnections(raw string) (int, error) {
	fields := strings.Split(strings.TrimSpace(raw), "\t")
	if len(fields) != 2 || fields[0] != "Threads_connected" {
		return 0, errors.New("MySQL 连接统计结果无效")
	}
	count, err := strconv.Atoi(fields[1])
	if err != nil || count < 0 || count > 1000000 {
		return 0, errors.New("MySQL 连接统计值无效")
	}
	return count, nil
}
