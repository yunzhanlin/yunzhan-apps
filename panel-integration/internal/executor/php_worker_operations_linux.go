//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type phpWorkerOperationRecord struct {
	core.PHPWorkerOperation
	Input       core.PHPWorker `json:"input"`
	ConfirmName string         `json:"confirm_name,omitempty"`
}

func phpWorkerOperationPending(state string) bool { return state == "queued" || state == "running" }
func phpWorkerOperationReference(state string) bool {
	return phpWorkerOperationPending(state) || state == "needs_attention"
}
func (s *Service) phpWorkerOperationsDir() string {
	return filepath.Join(s.Config.StateDir, "php-worker-operations")
}

func readPHPWorkerOperations(dir string) ([]phpWorkerOperationRecord, error) {
	entries, e := os.ReadDir(dir)
	if errors.Is(e, os.ErrNotExist) {
		return []phpWorkerOperationRecord{}, nil
	}
	if e != nil {
		return nil, e
	}
	if e = ordinary(dir, true); e != nil {
		return nil, e
	}
	if len(entries) > 1024 {
		return nil, errors.New("PHP 进程操作记录过多")
	}
	out := []phpWorkerOperationRecord{}
	for _, entry := range entries {
		// Ignore unpublished atomic writes; they carry no acknowledged operation.
		if strings.HasPrefix(entry.Name(), ".panel-write-") {
			if e = ordinary(filepath.Join(dir, entry.Name()), false); e != nil {
				return nil, e
			}
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !core.ValidID(id) || entry.Name() != id+".json" {
			return nil, errors.New("PHP 进程操作目录包含未识别记录")
		}
		p := filepath.Join(dir, entry.Name())
		if e = ordinary(p, false); e != nil {
			return nil, e
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		var v phpWorkerOperationRecord
		if e = json.Unmarshal(b, &v); e != nil {
			return nil, e
		}
		r, found := runtimecatalog.Find(v.Input.ObservedReleaseID)
		if v.ID != id || !core.ValidID(v.SiteID) || !core.ValidID(v.WorkerID) || v.Input.ID != v.WorkerID || v.Input.SiteID != v.SiteID || core.ValidatePHPWorkerSpec(v.Input.PHPWorkerSpec) != nil || !found || r.Family != "php" {
			return nil, errors.New("PHP 进程操作元数据损坏")
		}
		switch v.Action {
		case "create", "start", "stop", "restart", "delete":
		default:
			return nil, errors.New("PHP 进程操作类型损坏")
		}
		switch v.State {
		case "queued", "running", "succeeded", "failed", "needs_attention", "resolved":
		default:
			return nil, errors.New("PHP 进程操作状态损坏")
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt == out[j].CreatedAt {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt < out[j].CreatedAt
	})
	return out, nil
}

func (s *Service) savePHPWorkerOperation(v phpWorkerOperationRecord) error {
	dir := s.phpWorkerOperationsDir()
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if e := ordinary(dir, true); e != nil {
		return e
	}
	v.UpdatedAt = core.Now()
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(dir, v.ID+".json"), b, 0600)
}

// Persist before acknowledgement. On restart an interrupted mutation is never
// silently replayed: its actual process/configuration must be inspected first.
func (s *Service) StartPHPWorkerOperations() error {
	s.phpWorkerQueueMu.Lock()
	defer s.phpWorkerQueueMu.Unlock()
	if s.phpWorkerQueueStarted {
		return nil
	}
	items, e := readPHPWorkerOperations(s.phpWorkerOperationsDir())
	if e != nil {
		return e
	}
	for _, v := range items {
		if v.State != "running" {
			continue
		}
		v.State, v.Error = "needs_attention", "执行器在操作完成前重启；请检查当前进程与日志，再重新执行操作。未将中断操作视为成功。"
		if worker, err := readPHPWorker(v.WorkerID); err == nil && worker.SiteID == v.SiteID {
			current := s.inspectPHPWorker(context.Background(), worker)
			v.Worker = &current
		} else if s.phpWorkerNoResources(context.Background(), v.Input) {
			// Crashes before create or after delete may leave no manifest. Only
			// release the reference with independent directory/process/boot proof.
			v.State, v.Error = "failed", "执行器中断了操作；已核对配置目录不存在、进程已停止且没有开机启动项。可重新创建进程。"
		}
		if e = s.savePHPWorkerOperation(v); e != nil {
			return e
		}
	}
	s.phpWorkerQueueWake = make(chan struct{}, 1)
	s.phpWorkerQueueStarted = true
	go s.phpWorkerOperationLoop()
	s.phpWorkerQueueWake <- struct{}{}
	return nil
}

func (s *Service) phpWorkerNoResources(ctx context.Context, worker core.PHPWorker) bool {
	if _, e := os.Lstat(phpWorkerDirectory(worker.ID)); !errors.Is(e, os.ErrNotExist) {
		return false
	}
	current := s.inspectPHPWorker(ctx, worker)
	if current.PID != 0 || (current.Status != "stopped" && current.Status != "failed") {
		return false
	}
	state, e := s.Config.Run(ctx, "/usr/bin/systemctl", "is-enabled", phpWorkerUnit(worker.ID))
	state = strings.TrimSpace(state)
	return state == "disabled" || e != nil && strings.HasPrefix(state, "Failed to get unit file state") && strings.Contains(state, "No such file or directory")
}

func (s *Service) enqueuePHPWorkerOperation(v core.PHPWorker, action, confirm string) (core.PHPWorkerOperation, error) {
	var out core.PHPWorkerOperation
	if !core.ValidID(v.ID) || core.ValidatePHPWorkerSpec(v.PHPWorkerSpec) != nil {
		return out, errors.New("PHP 进程配置无效")
	}
	r, found := runtimecatalog.Find(v.ObservedReleaseID)
	if !found || r.Family != "php" {
		return out, errors.New("网站 PHP 版本无效")
	}
	if action != "create" && action != "start" && action != "stop" && action != "restart" && action != "delete" {
		return out, errors.New("PHP 进程操作无效")
	}
	if action == "delete" && confirm != v.Name {
		return out, errors.New("请输入进程名称确认删除")
	}
	if action == "create" || action == "start" || action == "restart" {
		if _, e := s.phpWorkerBinding(v.SiteID, v.ObservedReleaseID); e != nil {
			return out, e
		}
		if _, e := phpWorkerScriptPath(filepath.Join(s.Config.SitesDir, v.SiteID, "public"), v.Entry); e != nil {
			return out, e
		}
	}
	unlock, e := s.lockRuntimeUse()
	if e != nil {
		return out, e
	}
	defer unlock()
	s.phpWorkerQueueMu.Lock()
	defer s.phpWorkerQueueMu.Unlock()
	if !s.phpWorkerQueueStarted {
		return out, errors.New("PHP 进程后台队列未就绪")
	}
	items, e := readPHPWorkerOperations(s.phpWorkerOperationsDir())
	if e != nil {
		return out, e
	}
	pending := 0
	for _, item := range items {
		if phpWorkerOperationPending(item.State) {
			pending++
			if item.SiteID == v.SiteID {
				return out, errors.New("该网站已有正在执行的 PHP 进程操作，请等待完成")
			}
		}
	}
	if pending >= 64 {
		return out, errors.New("PHP 进程操作队列已满")
	}
	// Retain the last 128 completed records; never prune live or unresolved work.
	completed := 0
	for _, item := range items {
		if !phpWorkerOperationReference(item.State) {
			completed++
		}
	}
	removed := 0
	for _, item := range items {
		if completed < 128 {
			break
		}
		if phpWorkerOperationReference(item.State) {
			continue
		}
		if e = os.Remove(filepath.Join(s.phpWorkerOperationsDir(), item.ID+".json")); e != nil {
			return out, e
		}
		completed--
		removed++
	}
	if len(items)-removed >= 1024 {
		return out, errors.New("PHP 进程操作记录需要清理，请先处理未决操作")
	}
	out = core.PHPWorkerOperation{ID: core.ID(), SiteID: v.SiteID, WorkerID: v.ID, Action: action, State: "queued", CreatedAt: core.Now(), UpdatedAt: core.Now()}
	if e = s.savePHPWorkerOperation(phpWorkerOperationRecord{PHPWorkerOperation: out, Input: v, ConfirmName: confirm}); e != nil {
		return out, e
	}
	select {
	case s.phpWorkerQueueWake <- struct{}{}:
	default:
	}
	return out, nil
}

func (s *Service) phpWorkerOperationLoop() {
	for range s.phpWorkerQueueWake {
		for {
			s.phpWorkerQueueMu.Lock()
			items, e := readPHPWorkerOperations(s.phpWorkerOperationsDir())
			var next *phpWorkerOperationRecord
			if e == nil {
				for _, v := range items {
					if v.State == "queued" {
						copy := v
						next = &copy
						break
					}
				}
			}
			if next != nil {
				next.State = "running"
				e = s.savePHPWorkerOperation(*next)
			}
			s.phpWorkerQueueMu.Unlock()
			if e != nil {
				log.Printf("PHP worker queue: %v", e)
				break
			}
			if next == nil {
				break
			}
			ctx := context.Background() // Browser disconnects do not cancel accepted work.
			var worker core.PHPWorker
			if next.Action == "create" {
				e = s.createPHPWorker(ctx, next.Input)
				if e == nil {
					worker, e = readPHPWorker(next.WorkerID)
					if e == nil {
						worker = s.inspectPHPWorker(ctx, worker)
					}
				}
			} else {
				worker, e = s.changePHPWorker(ctx, next.SiteID, next.WorkerID, next.Action, next.ConfirmName)
			}
			next.State = "succeeded"
			if e != nil {
				next.State, next.Error = "failed", e.Error()
			}
			if worker.ID != "" {
				next.Worker = &worker
			}
			s.phpWorkerQueueMu.Lock()
			if err := s.savePHPWorkerOperation(*next); err != nil {
				log.Printf("PHP worker operation %s outcome not persisted: %v", next.ID, err)
				s.phpWorkerQueueMu.Unlock()
				break
			}
			if e == nil {
				for _, old := range items {
					if old.State == "needs_attention" && old.WorkerID == next.WorkerID && old.SiteID == next.SiteID {
						old.State = "resolved"
						if err := s.savePHPWorkerOperation(old); err != nil {
							log.Printf("PHP worker interrupted operation reconciliation: %v", err)
						}
					}
				}
			}
			s.phpWorkerQueueMu.Unlock()
		}
	}
}

func (s *Service) phpWorkerPublicOperations(siteID string) ([]core.PHPWorkerOperation, error) {
	s.phpWorkerQueueMu.Lock()
	defer s.phpWorkerQueueMu.Unlock()
	items, e := readPHPWorkerOperations(s.phpWorkerOperationsDir())
	if e != nil {
		return nil, e
	}
	out := []core.PHPWorkerOperation{}
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].SiteID == siteID {
			out = append(out, items[i].PHPWorkerOperation)
		}
	}
	return out, nil
}

func (s *Service) phpWorkerOperation(siteID, id string) (core.PHPWorkerOperation, error) {
	if !core.ValidID(siteID) || !core.ValidID(id) {
		return core.PHPWorkerOperation{}, errors.New("PHP 进程操作标识无效")
	}
	items, e := s.phpWorkerPublicOperations(siteID)
	if e != nil {
		return core.PHPWorkerOperation{}, e
	}
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return core.PHPWorkerOperation{}, fmt.Errorf("网站中不存在该 PHP 进程操作")
}

func (s *Service) phpWorkerMutationBusy() error {
	s.phpWorkerQueueMu.Lock()
	defer s.phpWorkerQueueMu.Unlock()
	items, e := readPHPWorkerOperations(s.phpWorkerOperationsDir())
	if e != nil {
		return e
	}
	for _, item := range items {
		if item.State == "running" {
			return errors.New("正在执行 PHP 进程操作，请等待完成后再变更网站；原网站保持不变")
		}
	}
	return nil
}
