//go:build linux

package executor

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"local/panel/internal/core"
)

func (s *Service) loadBalanceAlertRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/load-balance-alert-events", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			respond(w, 400, map[string]string{"error": "告警源不接受自定义目标、游标或查询参数"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		feed, err := s.loadBalanceAlertFeed(r)
		if err != nil {
			respond(w, 409, map[string]string{"error": "负载均衡告警源无法完整核对，原状态保留"})
			return
		}
		respond(w, 200, feed)
	})
}
func (s *Service) loadBalanceAlertFeed(r *http.Request) (core.LoadBalanceAlertFeed, error) {
	feed := core.LoadBalanceAlertFeed{SchemaVersion: 1, Entries: []core.LoadBalanceAlertEntry{}}
	dir := s.moduleDir("load-balance")
	if err := s.wafOwnedDirectory(dir, false); errors.Is(err, os.ErrNotExist) {
		return feed, nil
	} else if err != nil {
		return feed, err
	}
	if _, err := loadBalancePrivateRead(filepath.Join(dir, "installed.json"), 32<<10); errors.Is(err, os.ErrNotExist) {
		return feed, nil
	} else if err != nil {
		return feed, err
	}
	version := s.loadBalanceHealthVersion()
	if version == "" {
		return feed, errors.New("安装身份无法核对")
	}
	// Historical signed implementations remain usable without claiming this
	// newly reviewed alert contract. Unknown future versions were rejected above.
	if version != "1.8.3" {
		return feed, nil
	}
	lock, err := s.lockWAFObservation()
	if err != nil {
		return feed, err
	}
	defer lock.Close()
	if _, err = os.Lstat(s.loadBalancePendingPath()); !errors.Is(err, os.ErrNotExist) {
		return feed, errors.New("负载均衡有待恢复事务")
	}
	if s.loadBalanceHistorySharedPending() != "" {
		return feed, errors.New("共享配置有待恢复事务")
	}
	entries, err := s.loadBalanceEntries()
	if err != nil {
		return feed, err
	}
	now := time.Now().UTC()
	nodes := 0
	for _, v := range entries {
		if err = r.Context().Err(); err != nil {
			return feed, err
		}
		if v.Removed || v.HealthCheck == nil {
			continue
		}
		nodes += len(v.Nodes)
		if len(feed.Entries) >= 8 || nodes > 32 {
			return feed, errors.New("告警源库存超限，不返回部分数据")
		}
		row := core.LoadBalanceAlertEntry{ID: core.Hash("load-balance-alert-entry:" + v.Domain)[:32], Revision: v.Revision, CheckedAt: now.Format(time.RFC3339Nano), Transitions: []core.LoadBalanceAlertTransition{}}
		state, e := s.readLoadBalanceHTTPState(v, now)
		if e != nil {
			return feed, e
		}
		if state != nil {
			row.Sequence, row.CheckedAt = state.Sequence, state.CheckedAt
			for _, event := range state.Transitions {
				if event.Revision != v.Revision {
					return feed, errors.New("同修订历史混入其他配置")
				}
				row.Transitions = append(row.Transitions, core.LoadBalanceAlertTransition{Sequence: event.Sequence, From: event.From, To: event.To, Time: event.At})
			}
		}
		feed.Entries = append(feed.Entries, row)
	}
	feed.Available = true
	return feed, core.ValidateLoadBalanceAlertFeed(feed, now)
}
