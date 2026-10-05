package core

import (
	"context"
	"database/sql"
	"errors"
	"local/panel/internal/appcatalog"
	"net/http"
)

type registryReceipt struct {
	AppID, Scope, Version, SHA256, Target, JobID, Provider string
}

func (s *Store) trackRegistryJob(item appcatalog.CatalogItem, scope, jobID string) error {
	_, err := s.DB.Exec(`INSERT INTO app_registry_pending(job_id,app_id,scope,version,sha256,target,provider,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(job_id) DO NOTHING`, jobID, item.ID, scope, item.Version, item.SHA256, item.Target, item.Provider, Now())
	if err == nil {
		var old registryReceipt
		err = s.DB.QueryRow(`SELECT app_id,scope,version,sha256,target,provider FROM app_registry_pending WHERE job_id=?`, jobID).Scan(&old.AppID, &old.Scope, &old.Version, &old.SHA256, &old.Target, &old.Provider)
		if err == nil && (old.AppID != item.ID || old.Scope != scope || old.Version != item.Version || old.SHA256 != item.SHA256 || old.Target != item.Target || old.Provider != item.Provider) {
			return errors.New("幂等任务已绑定不同的应用包版本")
		}
	}
	return err
}

func (s *Store) registryReceipts() (map[string]registryReceipt, error) {
	rows, err := s.DB.Query(`SELECT app_id,scope,version,sha256,target FROM app_registry_receipts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]registryReceipt{}
	for rows.Next() {
		var v registryReceipt
		if err = rows.Scan(&v.AppID, &v.Scope, &v.Version, &v.SHA256, &v.Target); err != nil {
			return nil, err
		}
		out[v.AppID+":"+v.Scope] = v
	}
	return out, rows.Err()
}

// A queued request is not an installation. Persist the receipt only after its
// real job succeeded; failures leave the previous version untouched.
func (a *Server) reconcileRegistryReceipts(ctx context.Context) error {
	rows, err := a.Store.DB.Query(`SELECT job_id,app_id,scope,version,sha256,target,provider FROM app_registry_pending ORDER BY created_at LIMIT 64`)
	if err != nil {
		return err
	}
	var pending []registryReceipt
	for rows.Next() {
		var v registryReceipt
		if err = rows.Scan(&v.JobID, &v.AppID, &v.Scope, &v.Version, &v.SHA256, &v.Target, &v.Provider); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range pending {
		state := ""
		if v.Provider == "compose" {
			var result DockerJobResult
			if err = a.Executor.Call(ctx, http.MethodGet, "/v1/docker/jobs/"+v.JobID, nil, &result); err != nil {
				continue
			}
			if result.ProjectID != v.Scope {
				continue
			}
			state = result.State
		} else {
			err = a.Store.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, v.JobID).Scan(&state)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
		}
		if state != "succeeded" && state != "failed" && state != "needs_attention" {
			continue
		}
		tx, err := a.Store.DB.Begin()
		if err != nil {
			return err
		}
		if state == "succeeded" {
			var previous registryReceipt
			readErr := tx.QueryRow(`SELECT version,sha256 FROM app_registry_receipts WHERE app_id=? AND scope=?`, v.AppID, v.Scope).Scan(&previous.Version, &previous.SHA256)
			write := errors.Is(readErr, sql.ErrNoRows)
			if readErr == nil {
				cmp, valid := appcatalog.CompareVersions(v.Version, previous.Version)
				write = valid && cmp >= 0
				if cmp == 0 && v.SHA256 != previous.SHA256 {
					err = errors.New("相同应用版本的安装记录出现包冲突")
				}
			} else if !write {
				err = readErr
			}
			if err == nil && write {
				_, err = tx.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(app_id,scope) DO UPDATE SET version=excluded.version,sha256=excluded.sha256,target=excluded.target,updated_at=excluded.updated_at`, v.AppID, v.Scope, v.Version, v.SHA256, v.Target, Now())
			}
		}
		if err == nil {
			_, err = tx.Exec(`DELETE FROM app_registry_pending WHERE job_id=?`, v.JobID)
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
