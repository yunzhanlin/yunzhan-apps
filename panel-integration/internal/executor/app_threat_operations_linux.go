//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type threatIDSOperationRecord struct {
	Format    int                      `json:"format"`
	Operation core.NetworkIDSOperation `json:"operation"`
}

func (s *Service) threatIDSOperationsDir() string {
	return filepath.Join(s.Config.StateDir, "network-ids-operations")
}
func validateThreatIDSOperation(v threatIDSOperationRecord) error {
	o := v.Operation
	if v.Format != 1 || !core.ValidID(o.ID) || core.ValidateNetworkIDSOperationRequest(core.NetworkIDSOperationRequest{Action: o.Action, Input: o.Input}) != nil || len(o.Error) > 2048 || len(o.Steps) > 16 {
		return errors.New("IDS 后台记录格式、动作或身份无效")
	}
	created, err := time.Parse(time.RFC3339Nano, o.CreatedAt)
	updated, updateErr := time.Parse(time.RFC3339Nano, o.UpdatedAt)
	if err != nil || updateErr != nil || created.Year() < 2026 || updated.Before(created) {
		return errors.New("IDS 后台记录时间无效")
	}
	switch o.State {
	case "queued", "running", "succeeded":
		if o.Error != "" {
			return errors.New("IDS 未完成错误不能混入成功或执行中状态")
		}
	case "failed", "needs-attention":
		if o.Error == "" {
			return errors.New("IDS 失败记录缺少原因")
		}
	default:
		return errors.New("IDS 后台记录状态未知")
	}
	for _, step := range o.Steps {
		if len(step.Message) < 1 || len(step.Message) > 2048 || !threatEVEText(step.Message, 2048, false) {
			return errors.New("IDS 后台步骤无效")
		}
		if _, err := time.Parse(time.RFC3339Nano, step.Time); err != nil {
			return errors.New("IDS 后台步骤时间无效")
		}
	}
	if o.Action == "ids-config" {
		if err := validateThreatIDSConfig(threatIDSConfig{Revision: o.Input.ExpectedRevision, Interface: o.Input.Interface, HomeNetworks: o.Input.HomeNetworks}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) readThreatIDSOperations() ([]threatIDSOperationRecord, error) {
	dir := s.threatIDSOperationsDir()
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return []threatIDSOperationRecord{}, nil
	} else if err != nil {
		return nil, err
	}
	if ruleFeedStoreParents(dir) != nil || ruleFeedStoreOwned(dir, true, 0700) != nil {
		return nil, errors.New("IDS 后台队列父目录、所有者或权限无效")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := file.ReadDir(129)
	file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 128 {
		return nil, errors.New("IDS 后台队列超过 128 份；记录和现场保留")
	}
	out := []threatIDSOperationRecord{}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !core.ValidID(id) || entry.Name() != id+".json" {
			return nil, errors.New("IDS 后台队列有未知或未完成落盘文件；未清理")
		}
		raw, err := ruleFeedStoreRead(root, entry.Name(), 48<<10, 0600)
		var v threatIDSOperationRecord
		if err != nil || decodeThreatIDSPrivateJSON(raw, &v) != nil || v.Operation.ID != id || validateThreatIDSOperation(v) != nil {
			return nil, errors.New("IDS 后台记录被改变、损坏或身份不符；停止自动变更")
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Operation.CreatedAt == out[j].Operation.CreatedAt {
			return out[i].Operation.ID < out[j].Operation.ID
		}
		return out[i].Operation.CreatedAt < out[j].Operation.CreatedAt
	})
	return out, nil
}

// Caller owns idsOperationMu. This directory is executor state only, never a
// request path. Original terminal receipts are immutable, including failures.
func (s *Service) saveThreatIDSOperation(v threatIDSOperationRecord) error {
	if err := validateThreatIDSOperation(v); err != nil {
		return err
	}
	dir := s.threatIDSOperationsDir()
	if err := ruleFeedStoreParents(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := ruleFeedStoreOwned(dir, true, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, v.Operation.ID+".json")
	if _, err := os.Lstat(path); err == nil {
		root, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		raw, readErr := ruleFeedStoreRead(root, filepath.Base(path), 48<<10, 0600)
		root.Close()
		var old threatIDSOperationRecord
		if readErr != nil || decodeThreatIDSPrivateJSON(raw, &old) != nil || validateThreatIDSOperation(old) != nil || old.Operation.ID != v.Operation.ID || old.Operation.Action != v.Operation.Action || !reflect.DeepEqual(old.Operation.Input, v.Operation.Input) || old.Operation.CreatedAt != v.Operation.CreatedAt {
			return errors.New("IDS 原任务绑定不能核对；未覆盖")
		}
		if old.Operation.State != "queued" && old.Operation.State != "running" {
			return errors.New("IDS 终态回执不可覆盖")
		}
		if old.Operation.State == "queued" && v.Operation.State != "running" || old.Operation.State == "running" && v.Operation.State != "succeeded" && v.Operation.State != "failed" && v.Operation.State != "needs-attention" {
			return errors.New("IDS 后台状态转换无效")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if v.Operation.State != "queued" {
		return errors.New("IDS 新任务须先持久化排队状态")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return atomicWrite(path, append(raw, '\n'), 0600)
}

// The worker lives in panel-executor.service, retaining the existing candidate
// PID/start-time/lock verification. It is not an unverified root oneshot.
func (s *Service) StartNetworkIDSOperations() error {
	s.idsOperationMu.Lock()
	defer s.idsOperationMu.Unlock()
	if s.idsOperationStarted {
		return s.idsOperationError
	}
	items, err := s.readThreatIDSOperations()
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Operation.State != "running" {
			continue
		}
		item.Operation.State, item.Operation.Error = "needs-attention", "执行器在原生操作完成前重启；原事务和日志保留，未重放启停或宣称成功。请刷新实际状态并显式恢复。"
		item.Operation.UpdatedAt = core.Now()
		if err := s.saveThreatIDSOperation(item); err != nil {
			return err
		}
	}
	s.idsOperationWake = make(chan struct{}, 1)
	s.idsOperationStarted = true
	go s.threatIDSOperationLoop()
	s.idsOperationWake <- struct{}{}
	return nil
}

func (s *Service) enqueueThreatIDSOperation(id string, in core.NetworkIDSOperationRequest) (core.NetworkIDSOperation, error) {
	var out core.NetworkIDSOperation
	if !core.ValidID(id) || core.ValidateNetworkIDSOperationRequest(in) != nil {
		return out, errors.New("IDS 后台身份或输入无效")
	}
	// Detach arrays/pointers before acknowledgement and background ownership.
	raw, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	in, err = core.DecodeNetworkIDSOperationRequest(raw)
	if err != nil {
		return out, err
	}
	s.idsOperationMu.Lock()
	defer s.idsOperationMu.Unlock()
	if !s.idsOperationStarted || s.idsOperationError != nil {
		return out, errors.New("IDS 后台队列未就绪；未执行")
	}
	items, err := s.readThreatIDSOperations()
	if err != nil {
		s.idsOperationError = err
		return out, err
	}
	for _, item := range items {
		if item.Operation.ID == id {
			if item.Operation.Action != in.Action || !reflect.DeepEqual(item.Operation.Input, in.Input) {
				return out, errors.New("IDS 原提交标识已绑定不同输入；未覆盖或重放")
			}
			return item.Operation, nil
		}
	}
	for _, item := range items {
		if item.Operation.State == "queued" || item.Operation.State == "running" {
			return out, errors.New("IDS 已有待执行或运行中的原生操作；未并发提交")
		}
	}
	if len(items) >= 128 {
		return out, errors.New("IDS 原生操作达到 128 份；原失败和终态记录保留，需受控归档")
	}
	if !s.moduleInstalled("network-threat-detection") {
		return out, errors.New("IDS 应用未安装；不接收原生操作")
	}
	now := core.Now()
	out = core.NetworkIDSOperation{ID: id, Action: in.Action, Input: in.Input, State: "queued", CreatedAt: now, UpdatedAt: now, Steps: []core.Step{{Time: now, Message: "原生操作已持久化排队；尚未宣称配置通过、采集启动或恢复完成"}}}
	if err := s.saveThreatIDSOperation(threatIDSOperationRecord{Format: 1, Operation: out}); err != nil {
		s.idsOperationError = err
		return core.NetworkIDSOperation{}, err
	}
	select {
	case s.idsOperationWake <- struct{}{}:
	default:
	}
	return out, nil
}

func (s *Service) threatIDSOperation(id string) (core.NetworkIDSOperation, error) {
	if !core.ValidID(id) {
		return core.NetworkIDSOperation{}, errors.New("IDS 后台任务标识无效")
	}
	s.idsOperationMu.Lock()
	defer s.idsOperationMu.Unlock()
	items, err := s.readThreatIDSOperations()
	if err != nil {
		return core.NetworkIDSOperation{}, err
	}
	for _, item := range items {
		if item.Operation.ID == id {
			return item.Operation, nil
		}
	}
	return core.NetworkIDSOperation{}, errors.New("IDS 原后台任务不存在；未创建替代记录")
}

func (s *Service) threatIDSOperationLoop() {
	for range s.idsOperationWake {
		s.drainThreatIDSOperations(s.moduleThreatIDSControl)
	}
}

func (s *Service) drainThreatIDSOperations(execute func(context.Context, string, core.AppModuleInput) (any, error)) {
	for {
		s.idsOperationMu.Lock()
		items, err := s.readThreatIDSOperations()
		var next *threatIDSOperationRecord
		if err == nil && s.idsOperationError == nil {
			for _, item := range items {
				if item.Operation.State == "queued" {
					copy := item
					next = &copy
					break
				}
			}
		}
		if next != nil {
			next.Operation.State, next.Operation.UpdatedAt = "running", core.Now()
			next.Operation.Steps = append(next.Operation.Steps, core.Step{Time: core.Now(), Message: "执行器已接管任务；正在独立核对安装、修订、程序、权限和配置"})
			err = s.saveThreatIDSOperation(*next)
		}
		if err != nil {
			s.idsOperationError = err
		}
		s.idsOperationMu.Unlock()
		if err != nil || next == nil {
			break
		}
		// No global executor mutex: IDS's existing kernel configuration lock
		// serializes install/uninstall/recovery, without blocking site jobs.
		ctx, cancel := context.WithTimeout(context.Background(), threatIDSOperationBudget)
		input := core.AppModuleInput{ExpectedRevision: next.Operation.Input.ExpectedRevision, NetworkInterface: next.Operation.Input.Interface, HomeNetworks: append([]string(nil), next.Operation.Input.HomeNetworks...), RuleProfile: next.Operation.Input.RuleProfile}
		if next.Operation.Input.Enabled != nil {
			input.Enabled = *next.Operation.Input.Enabled
		}
		result, executeErr := execute(ctx, next.Operation.Action, input)
		err = executeErr
		if result, ok := result.(map[string]any); err == nil && ok && (result["state"] == "recovering-runtime" || result["recovered"] == false) {
			err = errors.New("原生迁移恢复已调度但尚未核对完成；刷新实际状态，原任务未宣称恢复成功")
		}
		cancel()
		next.Operation.State = "succeeded"
		message := "受限原生操作已返回核对结果；当前状态请刷新实际报表，排队回执不是启动证明"
		if err != nil {
			next.Operation.State, next.Operation.Error = "needs-attention", threatIDSOperationError(err)
			message = "原生操作未通过完整核对；保留原事务、日志和任务，未自动重放"
		}
		next.Operation.UpdatedAt = core.Now()
		next.Operation.Steps = append(next.Operation.Steps, core.Step{Time: core.Now(), Message: message})
		s.idsOperationMu.Lock()
		if err := s.saveThreatIDSOperation(*next); err != nil {
			s.idsOperationError = err
			s.idsOperationMu.Unlock()
			break
		}
		s.idsOperationMu.Unlock()
	}
}

func threatIDSOperationError(err error) string {
	text := strings.ToValidUTF8(err.Error(), "?")
	if len(text) > 2048 {
		text = text[:2048]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	if text == "" {
		return "IDS 原生操作未通过核对"
	}
	return text
}

func (s *Service) networkIDSOperationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/network-ids/operations", func(w http.ResponseWriter, r *http.Request) {
		s.idsOperationMu.Lock()
		items, err := s.readThreatIDSOperations()
		s.idsOperationMu.Unlock()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		out := []core.NetworkIDSOperation{}
		for i := len(items) - 1; i >= 0 && len(out) < 16; i-- {
			out = append(out, items[i].Operation)
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/network-ids/operations/{operation}", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.threatIDSOperation(r.PathValue("operation"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/network-ids/operations/{operation}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		in, decodeErr := core.DecodeNetworkIDSOperationRequest(raw)
		if err != nil || decodeErr != nil {
			respond(w, 400, map[string]string{"error": "IDS 后台输入重复、未知或超限"})
			return
		}
		out, err := s.enqueueThreatIDSOperation(r.PathValue("operation"), in)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 202, out)
	})
}
