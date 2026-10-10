//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// A durable reservation precedes job creation. An uncertain reservation never
// generates a replacement ID; the operator must inspect it and explicitly resume.
type remoteSyncPlan struct {
	ID             string   `json:"id"`
	TargetID       string   `json:"remote_target_id"`
	SiteID         string   `json:"site_id"`
	Revision       int64    `json:"revision"`
	TargetRevision int64    `json:"remote_target_revision"`
	SpecSHA        string   `json:"spec_sha256"`
	Excludes       []string `json:"excludes"`
	Interval       int      `json:"interval"`
	Enabled        bool     `json:"enabled"`
	NextRunAt      string   `json:"next_run_at,omitempty"`
	PendingJobID   string   `json:"pending_job_id,omitempty"`
	LastJobID      string   `json:"last_job_id,omitempty"`
	LastState      string   `json:"last_state"`
	LastError      string   `json:"last_error,omitempty"`
	LastFinishedAt string   `json:"last_finished_at,omitempty"`
}

func (s *Service) remotePlanPath(id string) string {
	return filepath.Join(s.remoteSyncDir(), "plans", id+".json")
}
func remotePlanBlockedID(id string) string { return "files-sync/remote-plan/" + id }
func validateRemotePlan(p remoteSyncPlan) error {
	if !syncPlanID.MatchString(p.ID) || !syncPlanID.MatchString(p.TargetID) || !core.ValidID(p.SiteID) || p.Revision < 1 || p.TargetRevision < 1 || !coreSHA.MatchString(p.SpecSHA) || p.Interval < 60 || p.Interval > 86400 || len(p.Excludes) > 64 || p.PendingJobID != "" && !core.ValidID(p.PendingJobID) || p.LastJobID != "" && !core.ValidID(p.LastJobID) {
		return errors.New("远端定时计划身份、修订号或参数无效")
	}
	for _, prefix := range p.Excludes {
		if !core.ValidFilePath(prefix, false) {
			return errors.New("远端计划排除路径无效")
		}
	}
	if !sort.StringsAreSorted(p.Excludes) {
		return errors.New("远端计划排除项未规范排序")
	}
	switch p.LastState {
	case "pending", "queueing", "queued", "succeeded", "paused", "paused-error", "removed":
	default:
		return errors.New("远端计划状态无效")
	}
	if p.Enabled {
		if p.LastState == "paused" || p.LastState == "paused-error" || p.LastState == "removed" {
			return errors.New("远端计划启用与状态矛盾")
		}
		if _, err := time.Parse(time.RFC3339, p.NextRunAt); err != nil {
			return errors.New("远端计划下次执行时间无效")
		}
	}
	if (p.LastState == "queueing" || p.LastState == "queued") && p.PendingJobID == "" {
		return errors.New("远端计划缺少已预留任务身份")
	}
	if p.LastFinishedAt != "" {
		if _, err := time.Parse(time.RFC3339, p.LastFinishedAt); err != nil {
			return errors.New("远端计划完成时间无效")
		}
	}
	return nil
}
func (s *Service) readRemotePlan(id string) (remoteSyncPlan, error) {
	var p remoteSyncPlan
	if !syncPlanID.MatchString(id) {
		return p, errors.New("远端计划标识无效")
	}
	if err := remoteRead(s.remotePlanPath(id), &p); err != nil {
		return p, err
	}
	if p.ID != id {
		return p, errors.New("远端计划身份与文件名不匹配")
	}
	return p, validateRemotePlan(p)
}
func (s *Service) allRemotePlans() ([]remoteSyncPlan, error) {
	items, err := os.ReadDir(filepath.Join(s.remoteSyncDir(), "plans"))
	if errors.Is(err, os.ErrNotExist) {
		return []remoteSyncPlan{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err = remotePrivateDirectory(s.remoteSyncDir()); err != nil {
		return nil, err
	}
	if err = remotePrivateDirectory(filepath.Join(s.remoteSyncDir(), "plans")); err != nil {
		return nil, err
	}
	if len(items) > 16 {
		return nil, errors.New("远端计划超过 16 个保留记录上限；未返回不完整列表")
	}
	rows := []remoteSyncPlan{}
	for _, entry := range items {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("远端计划目录含未知记录")
		}
		p, e := s.readRemotePlan(strings.TrimSuffix(entry.Name(), ".json"))
		if e != nil {
			return nil, e
		}
		rows = append(rows, p)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}
func (s *Service) writeRemotePlan(p remoteSyncPlan) error {
	if err := validateRemotePlan(p); err != nil {
		return err
	}
	if err := moduleWrite(s.remotePlanPath(p.ID), p); err != nil {
		s.blockModuleAutomation(remotePlanBlockedID(p.ID))
		return err
	}
	fresh, err := s.readRemotePlan(p.ID)
	if err != nil || !reflect.DeepEqual(fresh, p) {
		s.blockModuleAutomation(remotePlanBlockedID(p.ID))
		return errors.New("远端计划保存后身份不能核对，后台写入安全暂停")
	}
	return nil
}
func (s *Service) pauseRemotePlanError(p *remoteSyncPlan, detail string) {
	p.Enabled = false
	p.NextRunAt = ""
	p.LastState = "paused-error"
	p.LastError = detail
	if err := s.writeRemotePlan(*p); err != nil {
		s.blockModuleAutomation(remotePlanBlockedID(p.ID))
	}
}
func (s *Service) remotePlanPendingJob(p remoteSyncPlan) (remoteSyncJob, error) {
	j, err := s.readRemoteJob(p.PendingJobID)
	if err != nil {
		return j, err
	}
	if j.PlanID != p.ID || j.PlanRevision < 1 || j.PlanRevision > p.Revision || j.TargetID != p.TargetID || j.SiteID != p.SiteID || j.SpecSHA != p.SpecSHA || !reflect.DeepEqual(j.Excludes, p.Excludes) {
		return j, errors.New("远端计划预留任务绑定不能核对")
	}
	return j, nil
}
func (s *Service) remotePlanJobAllowed(j remoteSyncJob) error {
	if j.PlanID == "" {
		return nil
	}
	p, err := s.readRemotePlan(j.PlanID)
	if err != nil || s.moduleAutoBlocked[remotePlanBlockedID(j.PlanID)] || !p.Enabled || p.LastState != "queued" || p.PendingJobID != j.ID || p.Revision != j.PlanRevision || p.TargetRevision != j.Revision || p.TargetID != j.TargetID || p.SiteID != j.SiteID || p.SpecSHA != j.SpecSHA || !reflect.DeepEqual(p.Excludes, j.Excludes) {
		return errors.New("远端计划已暂停、修订或尚未持久确认；停止后续文件交接")
	}
	return nil
}

// Only an explicit owner action can settle an uncertain/missing reservation.
// The private no-follow reader must prove absence, not merely fail to read it.
func (s *Service) settleRemotePlanReservation(p *remoteSyncPlan) error {
	if p.PendingJobID == "" {
		return nil
	}
	j, e := s.remotePlanPendingJob(*p)
	if errors.Is(e, os.ErrNotExist) && !p.Enabled && (p.LastState == "paused-error" || p.LastState == "paused" || p.LastState == "removed") {
		p.LastJobID = p.PendingJobID
	} else if e != nil {
		return e
	} else if j.State == "queued" || j.State == "running" {
		return errors.New("原任务尚未结束；先请求取消并核对，不创建替代任务")
	} else {
		p.LastJobID = j.ID
		p.LastFinishedAt = j.FinishedAt
	}
	p.PendingJobID = ""
	return nil
}

func (s *Service) remotePlanControlRecordFailed(action string, in core.AppModuleInput) {
	if action != "schedule-remote-plan" && action != "resume-remote-plan" {
		return
	}
	s.blockModuleAutomation(remotePlanBlockedID(in.ResourceID))
	if p, e := s.readRemotePlan(in.ResourceID); e == nil {
		s.pauseRemotePlanError(&p, "控制操作结果或历史不能持久核对；计划安全暂停，请核对原策略与任务后重新启用")
	}
}

func remotePlanInput(action string, in core.AppModuleInput) error {
	// No credentials, arbitrary shell/targets, manual job ID or realtime policy
	// is accepted by a periodic-plan action, even if those fields are valid elsewhere.
	rest := in
	rest.ResourceID = ""
	rest.ExpectedRevision = 0
	if action == "schedule-remote-plan" {
		rest.RemoteTargetID = ""
		rest.SiteID = ""
		rest.Excludes = nil
		rest.Interval = 0
		rest.Enabled = false
		rest.RemoteTargetRevision = 0
	}
	if action == "resume-remote-plan" {
		rest.RemoteTargetRevision = 0
	}
	if !reflect.DeepEqual(rest, core.AppModuleInput{}) {
		return errors.New("远端定时计划包含不适用字段；实时策略和认证材料须使用对应操作")
	}
	return nil
}
func (s *Service) moduleRemotePlans(action string, in core.AppModuleInput) (any, error) {
	if err := remotePlanInput(action, in); err != nil {
		return nil, err
	}
	rows, err := s.allRemotePlans()
	if err != nil {
		return nil, err
	}
	if action == "remote-plans" {
		for i := range rows {
			if s.moduleAutoBlocked[remotePlanBlockedID(rows[i].ID)] {
				rows[i].Enabled = false
				rows[i].LastState = "paused-error"
				rows[i].LastError = "后台状态不能持久核对，安全暂停；检查存储和原任务后显式重新启用"
			}
		}
		return map[string]any{"remote_plans": rows, "scope": remoteSyncScope}, nil
	}
	if !syncPlanID.MatchString(in.ResourceID) {
		return nil, errors.New("远端计划标识应为 3–64 位小写字母数字或短横线")
	}
	p, err := s.readRemotePlan(in.ResourceID)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if exists && in.ExpectedRevision != p.Revision || !exists && in.ExpectedRevision != 0 {
		return nil, errors.New("远端计划修订号改变，请刷新并重新选择")
	}
	now := time.Now().UTC()
	if action == "schedule-remote-plan" {
		if exists && (p.TargetID != in.RemoteTargetID || p.SiteID != in.SiteID) {
			return nil, errors.New("已有远端计划来源与目标不可更换；新策略使用新标识")
		}
		if exists && p.PendingJobID != "" {
			if p.Enabled {
				return nil, errors.New("计划仍启用且有原预留任务；先暂停并核对终态")
			}
			if err = s.settleRemotePlanReservation(&p); err != nil {
				return nil, err
			}
		}
		if !exists && len(rows) >= 16 {
			return nil, errors.New("最多保留 16 个远端计划记录，移除保留原身份与证据")
		}
		for _, other := range rows {
			if other.ID != in.ResourceID && other.TargetID == in.RemoteTargetID && other.LastState != "removed" {
				return nil, errors.New("每个远端连接只允许一个未移除定时计划")
			}
		}
		cfg, e := s.readRemoteConfig(in.RemoteTargetID)
		if e != nil {
			return nil, e
		}
		if !cfg.Enabled || cfg.Revision != in.RemoteTargetRevision {
			return nil, errors.New("请先核对并选择已启用连接的当前修订号")
		}
		candidate := remoteSyncPlan{ID: in.ResourceID, TargetID: cfg.ID, SiteID: in.SiteID, Revision: p.Revision + 1, TargetRevision: cfg.Revision, SpecSHA: cfg.SpecSHA, Excludes: append([]string{}, in.Excludes...), Interval: in.Interval, Enabled: in.Enabled, LastState: "paused", LastJobID: p.LastJobID, LastFinishedAt: p.LastFinishedAt}
		sort.Strings(candidate.Excludes)
		if candidate.Enabled {
			candidate.LastState = "pending"
			candidate.NextRunAt = now.Add(time.Duration(candidate.Interval) * time.Second).Format(time.RFC3339)
		}
		if e = validateRemotePlan(candidate); e != nil {
			return nil, e
		}
		f, e := s.openFiles(candidate.SiteID)
		if e != nil {
			return nil, e
		}
		f.Close()
		cp, e := s.readRemoteCheckpoint(cfg, candidate.SiteID)
		if e != nil {
			return nil, e
		}
		if cp.Pending != nil {
			return nil, errors.New("先核对并恢复远端文件交接")
		}
		// Binding an empty source is durable before a plan can become active.
		if e = moduleWrite(s.remoteCheckpointPath(cfg.ID), cp); e != nil {
			return nil, e
		}
		p = candidate
	} else {
		if !exists {
			return nil, errors.New("远端定时计划不存在")
		}
		switch action {
		case "pause-remote-plan", "remove-remote-plan":
			p.Enabled = false
			p.Revision++
			p.NextRunAt = ""
			p.LastState = "paused"
			p.LastError = ""
			if action == "remove-remote-plan" {
				p.LastState = "removed"
			}
		case "resume-remote-plan":
			if p.LastState == "removed" {
				return nil, errors.New("计划已移除；保留原记录，需显式重新保存策略")
			}
			cfg, e := s.readRemoteConfig(p.TargetID)
			if e != nil {
				return nil, e
			}
			if !cfg.Enabled || cfg.SpecSHA != p.SpecSHA || cfg.Revision != in.RemoteTargetRevision {
				return nil, errors.New("先选择并核对当前已启用连接修订号")
			}
			cp, e := s.readRemoteCheckpoint(cfg, p.SiteID)
			if e != nil {
				return nil, e
			}
			if cp.Pending != nil {
				return nil, errors.New("仍有远端交接待恢复，不重新启用计划")
			}
			if p.PendingJobID != "" {
				if e = s.settleRemotePlanReservation(&p); e != nil {
					return nil, e
				}
			}
			f, e := s.openFiles(p.SiteID)
			if e != nil {
				return nil, e
			}
			f.Close()
			p.Enabled = true
			p.Revision++
			p.TargetRevision = cfg.Revision
			p.LastState = "pending"
			p.LastError = ""
			p.NextRunAt = now.Add(time.Duration(p.Interval) * time.Second).Format(time.RFC3339)
		default:
			return nil, errors.New("远端计划动作无效")
		}
	}
	if err = s.writeRemotePlan(p); err != nil {
		return nil, err
	}
	delete(s.moduleAutoBlocked, remotePlanBlockedID(p.ID))
	if !p.Enabled && p.PendingJobID != "" {
		if _, e := s.cancelRemoteSync(core.AppModuleInput{RemoteRequestID: p.PendingJobID}); e != nil {
			if p.LastState != "removed" {
				s.pauseRemotePlanError(&p, "计划已暂停，但原取消回执不能核对；保留预留标识，先检查原任务后显式重新启用")
			}
			return nil, errors.New("计划已暂停并阻止后续交接，但原任务取消记录不能核对；刷新任务列表，勿重新提交")
		}
	}
	return map[string]any{"remote_plan": p, "scope": remoteSyncScope}, nil
}

// Caller holds Service.mu. Only enqueue; actual SFTP execution is outside mu.
func (s *Service) scheduleRemotePlans(now time.Time) {
	rows, err := s.allRemotePlans()
	if err != nil {
		return
	}
	for _, p := range rows {
		if !p.Enabled || s.moduleAutoBlocked[remotePlanBlockedID(p.ID)] {
			continue
		}
		cfg, e := s.readRemoteConfig(p.TargetID)
		if e != nil || !cfg.Enabled || cfg.Revision != p.TargetRevision || cfg.SpecSHA != p.SpecSHA {
			s.pauseRemotePlanError(&p, "连接策略已改变或不可核对；不自动信任新凭据，请核对后显式重新启用")
			continue
		}
		if p.PendingJobID != "" {
			if p.LastState == "queueing" {
				s.pauseRemotePlanError(&p, "任务接受阶段曾中断；保留原预留标识，请核对原任务后显式恢复")
				continue
			}
			j, e := s.remotePlanPendingJob(p)
			if e != nil {
				s.pauseRemotePlanError(&p, "预留任务丢失或身份异常；不生成替代标识，请核对原记录")
				continue
			}
			if j.State == "queued" || j.State == "running" {
				continue
			}
			p.LastJobID = j.ID
			p.LastFinishedAt = j.FinishedAt
			if j.State != "succeeded" {
				s.pauseRemotePlanError(&p, "原任务未完整成功（"+j.State+"）；保留检查点、冲突和备份，核对后显式重新启用")
				continue
			}
			p.PendingJobID = ""
			p.LastState = "succeeded"
			p.LastError = ""
			p.NextRunAt = now.Add(time.Duration(p.Interval) * time.Second).Format(time.RFC3339)
			if e = s.writeRemotePlan(p); e != nil {
				continue
			}
			continue
		}
		due, e := time.Parse(time.RFC3339, p.NextRunAt)
		if e != nil || now.Before(due) {
			continue
		}
		busy, e := s.remoteTargetBusy(p.TargetID)
		if e != nil {
			s.pauseRemotePlanError(&p, "远端任务或检查点不能核对；未自动排队")
			continue
		}
		if busy {
			continue
		}
		p.PendingJobID = core.ID()
		p.LastState = "queueing"
		if e = s.writeRemotePlan(p); e != nil {
			continue
		}
		_, e = s.queueRemotePlanSync(cfg, core.AppModuleInput{SiteID: p.SiteID, RemoteRequestID: p.PendingJobID, ExpectedRevision: p.TargetRevision, Excludes: p.Excludes}, p.ID, p.Revision)
		if e != nil {
			s.pauseRemotePlanError(&p, "原任务接受结果不能确认；保留预留标识，不重发。请检查容量、来源与持久记录")
			continue
		}
		p.LastState = "queued"
		_ = s.writeRemotePlan(p)
	}
}
