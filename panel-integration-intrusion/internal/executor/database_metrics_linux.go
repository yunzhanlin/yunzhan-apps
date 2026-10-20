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

func (s *Service) databaseMetricRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/databases/metrics", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Targets []core.DatabaseMetricTarget `json:"targets"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if len(in.Targets) > 20 {
			respond(w, 400, map[string]string{"error": "实例数量超出统计上限"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		metrics := []core.DatabaseMetric{}
		count := 0
		for _, target := range in.Targets {
			count += len(target.Names)
			if !core.ValidID(target.ServerID) || count > 200 || len(target.Names) == 0 {
				respond(w, 400, map[string]string{"error": "数据库统计范围无效"})
				return
			}
			for _, name := range target.Names {
				if !core.ValidDatabaseName(name) {
					respond(w, 400, map[string]string{"error": "数据库名无效"})
					return
				}
			}
			manifest, err := readMySQL(target.ServerID)
			if err != nil {
				continue
			}
			state, _ := RunCommand(ctx, "/usr/bin/systemctl", "is-active", mysqlUnit(target.ServerID))
			if strings.TrimSpace(state) != "active" || !manifest.Ready {
				continue
			}
			rows, err := mysqlDatabaseMetrics(ctx, manifest.Server, target.Names)
			if err != nil {
				continue
			}
			metrics = append(metrics, rows...)
		}
		respond(w, 200, map[string]any{"metrics": metrics})
	})
}

func mysqlDatabaseMetrics(ctx context.Context, server core.DatabaseServer, names []string) ([]core.DatabaseMetric, error) {
	if len(names) == 0 || len(names) > 200 {
		return nil, errors.New("数据库数量无效")
	}
	quoted := make([]string, 0, len(names))
	wanted := map[string]bool{}
	for _, name := range names {
		if !core.ValidDatabaseName(name) {
			return nil, errors.New("数据库名无效")
		}
		quoted = append(quoted, "'"+name+"'")
		wanted[name] = true
	}
	sql := "SELECT s.SCHEMA_NAME,s.DEFAULT_CHARACTER_SET_NAME,COALESCE(SUM(t.DATA_LENGTH+t.INDEX_LENGTH),0) FROM information_schema.SCHEMATA s LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA=s.SCHEMA_NAME WHERE s.SCHEMA_NAME IN (" + strings.Join(quoted, ",") + ") GROUP BY s.SCHEMA_NAME,s.DEFAULT_CHARACTER_SET_NAME ORDER BY s.SCHEMA_NAME;\n"
	raw, err := mysqlQuery(ctx, server, sql)
	if err != nil {
		return nil, err
	}
	return parseDatabaseMetrics(server.ID, raw, wanted)
}

func parseDatabaseMetrics(serverID, raw string, wanted map[string]bool) ([]core.DatabaseMetric, error) {
	out := []core.DatabaseMetric{}
	if raw == "" {
		return out, nil
	}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !wanted[fields[0]] || !core.ValidDatabaseName(fields[0]) {
			return nil, errors.New("数据库容量结果无效")
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 || len(fields[1]) > 40 {
			return nil, errors.New("数据库容量结果无效")
		}
		out = append(out, core.DatabaseMetric{ServerID: serverID, Name: fields[0], Bytes: size, Charset: fields[1]})
	}
	return out, nil
}
