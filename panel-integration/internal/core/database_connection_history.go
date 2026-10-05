package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

// A nil count means the source could not be read. It must not be graphed as zero.
type DatabaseConnectionSample struct {
	SampledAt int64 `json:"sampled_at"`
	MySQL     *int  `json:"mysql"`
	Redis     *int  `json:"redis"`
}

func (s *Store) migrateDatabaseConnectionHistory() error {
	_, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS database_connection_samples(
 sampled_at INTEGER PRIMARY KEY,
 mysql_clients INTEGER CHECK(mysql_clients BETWEEN 0 AND 1000000),
 redis_clients INTEGER CHECK(redis_clients BETWEEN 0 AND 1000000));
 INSERT OR IGNORE INTO schema_migrations VALUES(35,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return err
}

func (s *Store) RecordDatabaseConnectionSample(at time.Time, mysql, redis *int) error {
	for _, count := range []*int{mysql, redis} {
		if count != nil && (*count < 0 || *count > 1000000) {
			return errors.New("数据库连接数样本无效")
		}
	}
	minute := at.Unix() / 60 * 60
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO database_connection_samples(sampled_at,mysql_clients,redis_clients) VALUES(?,?,?)
 ON CONFLICT(sampled_at) DO UPDATE SET mysql_clients=excluded.mysql_clients,redis_clients=excluded.redis_clients`, minute, mysql, redis); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM database_connection_samples WHERE sampled_at<?`, at.Add(-24*time.Hour).Unix()/60*60); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DatabaseConnectionHistory(now time.Time) ([]DatabaseConnectionSample, error) {
	rows, err := s.DB.Query(`SELECT sampled_at,mysql_clients,redis_clients FROM database_connection_samples
 WHERE sampled_at>=? AND sampled_at<=? ORDER BY sampled_at LIMIT 1441`, now.Add(-24*time.Hour).Unix(), now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DatabaseConnectionSample{}
	for rows.Next() {
		var point DatabaseConnectionSample
		var mysql, redis sql.NullInt64
		if err = rows.Scan(&point.SampledAt, &mysql, &redis); err != nil {
			return nil, err
		}
		if mysql.Valid {
			value := int(mysql.Int64)
			point.MySQL = &value
		}
		if redis.Valid {
			value := int(redis.Int64)
			point.Redis = &value
		}
		out = append(out, point)
	}
	return out, rows.Err()
}

func RunDatabaseConnectionWorker(ctx context.Context, store *Store, executor *ExecutorClient) {
	collect := func() {
		at := time.Now()
		var mysql, redis *int
		servers, err := store.DatabaseServers()
		if err == nil {
			ids := []string{}
			blocked := false
			for _, server := range servers {
				if server.Status == "running" {
					ids = append(ids, server.ID)
				} else if server.Status != "stopped" {
					blocked = true
				}
			}
			if len(ids) == 0 && !blocked {
				zero := 0
				mysql = &zero
			}
			if !blocked && len(ids) > 0 && len(ids) <= 20 {
				callCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
				var result struct {
					Connections []DatabaseConnection `json:"connections"`
				}
				err = executor.Call(callCtx, http.MethodPost, "/v1/databases/connections", map[string]any{"server_ids": ids}, &result)
				cancel()
				if err == nil && len(result.Connections) == len(ids) {
					wanted := map[string]bool{}
					for _, id := range ids {
						wanted[id] = true
					}
					total := 0
					valid := true
					for _, item := range result.Connections {
						if !wanted[item.ServerID] || item.Clients < 0 || item.Clients > 1000000 {
							valid = false
							break
						}
						delete(wanted, item.ServerID)
						total += item.Clients
					}
					if valid && len(wanted) == 0 && total <= 1000000 {
						mysql = &total
					}
				}
			}
		}
		callCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		var instances struct {
			Instances []RedisInstance `json:"instances"`
		}
		err = executor.Call(callCtx, http.MethodGet, "/v1/redis/instances", nil, &instances)
		cancel()
		if err == nil {
			total := 0
			valid := true
			for _, item := range instances.Instances {
				if item.Status == "needs_attention" {
					valid = false
					break
				}
				if item.Status != "running" {
					continue
				}
				if item.Clients < 0 || item.Clients > 1000000 {
					valid = false
					break
				}
				total += item.Clients
			}
			if valid && total <= 1000000 {
				redis = &total
			}
		}
		_ = store.RecordDatabaseConnectionSample(at, mysql, redis)
	}
	collect()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		}
	}
}
