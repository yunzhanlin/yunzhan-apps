//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"local/panel/internal/core"
)

func (s *Service) loadBalanceTrafficAlertRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/load-balance-traffic-alert-events", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			respond(w, 400, map[string]string{"error": "切流告警源不接受自定义查询、目标或路径"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Context().Err() != nil {
			return // Do not start a full scan after a cancelled caller waited on the lock.
		}
		feed, e := s.loadBalanceTrafficAlertFeed(r)
		if e != nil {
			respond(w, 409, map[string]string{"error": "切流事务或调度库存无法完整核对，保留原证据"})
			return
		}
		respond(w, 200, feed)
	})
}
func (s *Service) loadBalanceTrafficAlertFeed(r *http.Request) (core.LoadBalanceTrafficFeed, error) {
	f := core.LoadBalanceTrafficFeed{SchemaVersion: 1, Records: []core.LoadBalanceTrafficRecord{}, WorkerState: "unknown"}
	dir := s.moduleDir("load-balance")
	if e := s.wafOwnedDirectory(dir, false); errors.Is(e, os.ErrNotExist) {
		return f, nil
	} else if e != nil {
		return f, e
	}
	if _, e := loadBalancePrivateRead(filepath.Join(dir, "installed.json"), 32<<10); errors.Is(e, os.ErrNotExist) {
		return f, nil
	} else if e != nil {
		return f, e
	}
	version := s.loadBalanceHealthVersion()
	if version == "" {
		return f, errors.New("切流安装身份不可核对")
	}
	if version != "1.8.4" && version != "1.8.5" {
		return f, nil
	}
	lock, e := s.lockWAFObservation()
	if e != nil {
		return f, e
	}
	defer lock.Close()
	if s.loadBalanceHistorySharedPending() != "" {
		return f, errors.New("共享配置存在待核对事务")
	}
	inventory, e := s.loadBalanceHistoryInventory(r.Context())
	if e != nil {
		return f, e
	}
	// Read-only observation deliberately permits a trusted load-balancer pending
	// transaction. It does not recover/reload/probe or authorize any writer.
	var pending loadBalanceTransaction
	if inventory.Pending {
		pending, e = s.readLoadBalanceTransaction()
		if e != nil {
			return f, e
		}
	}
	pendingMatched := !inventory.Pending || pending.Format < 3
	for _, row := range inventory.Rows {
		if e = r.Context().Err(); e != nil {
			return f, e
		}
		if row.Format < 3 {
			continue
		}
		state := row.State
		if state != "committed" && state != "recovered" {
			state = "pending"
		}
		if inventory.Pending && pending.ID == row.ID {
			if row.Archived {
				return f, errors.New("待核对事务身份已归档")
			}
			p := filepath.Join(filepath.Dir(s.loadBalancePendingPath()), row.ID+".json")
			b, err := loadBalancePrivateRead(p, 256<<10)
			if err != nil {
				return f, err
			}
			var original loadBalanceTransaction
			if decodeFTPPrivateJSON(b, &original) != nil || s.loadBalanceTransactionContract(original) != nil {
				return f, errors.New("原切流事务不可核对")
			}
			copy := pending
			copy.State = original.State
			a, _ := json.Marshal(copy)
			b, _ = json.Marshal(original)
			if !bytes.Equal(a, b) {
				return f, errors.New("待核对切流与原恢复记录内容不符")
			}
			pendingMatched = true
			state = "pending"
		}
		f.Records = append(f.Records, core.LoadBalanceTrafficRecord{ID: row.ID, EntryID: core.Hash("load-balance-alert-entry:" + row.Domain)[:32], State: state, CreatedAt: row.CreatedAt})
	}
	if !pendingMatched {
		return f, errors.New("待核对切流事务缺少原历史身份")
	}
	s.lbHealthStatusMu.Lock()
	at, workerError := s.lbHealthWorkerCheckedAt, s.lbHealthWorkerError
	s.lbHealthStatusMu.Unlock()
	now := time.Now().UTC()
	if at != "" {
		checked, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return f, err
		}
		f.WorkerState, f.WorkerCheckedAt = "clear", at
		if workerError != "" {
			f.WorkerState = "error"
		}
		if now.Sub(checked) > 15*time.Second {
			f.WorkerState = "stale"
		}
	}
	f.Available = true
	return f, core.ValidateLoadBalanceTrafficFeed(f, now)
}
