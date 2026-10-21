package core

import (
	"context"
	"encoding/json"
	"time"
)

// Reads the independent executor's durable completion. It never restarts SQL.
func RunDatabaseOverwriteReconciler(ctx context.Context, s *Store, ex *ExecutorClient) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		rows, e := s.DB.Query(`SELECT j.payload FROM mysql_jobs j JOIN mysql_databases d ON d.id=json_extract(j.payload,'$.database.id') WHERE j.kind='overwrite_database' AND j.state IN ('failed','needs_attention') AND d.status='needs_attention' AND j.rowid=(SELECT MAX(k.rowid) FROM mysql_jobs k WHERE json_extract(k.payload,'$.database.id')=d.id AND k.kind!='backup_database') ORDER BY j.updated_at DESC LIMIT 20`)
		if e != nil {
			continue
		}
		operations := []DatabaseOperation{}
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) != nil {
				continue
			}
			var op DatabaseOperation
			if json.Unmarshal([]byte(raw), &op) == nil && op.Action == "overwrite_database" && ValidID(op.JobID) {
				operations = append(operations, op)
			}
		}
		rows.Close()
		for _, op := range operations {
			var result DatabaseResult
			if e = ex.Call(ctx, "GET", "/v1/databases/jobs/"+op.JobID, nil, &result); e != nil {
				continue
			}
			if (result.State == "succeeded" || result.State == "failed") && result.DatabaseStatus == "ready" {
				_ = s.FinishDatabase(op, result)
			}
		}
	}
}
