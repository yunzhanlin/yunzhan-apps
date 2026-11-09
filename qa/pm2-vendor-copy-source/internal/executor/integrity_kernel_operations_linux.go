//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

type integrityKernelStarted struct {
	Format      int    `json:"format"`
	ID          string `json:"id"`
	RequestSHA  string `json:"request_sha"`
	InstalledAt string `json:"installed_at"`
	StartedAt   string `json:"started_at"`
}

func (s *Service) integrityKernelInstalled(applications ...string) (map[string]any, error) {
	application, err := integrityKernelApplicationArgument(applications)
	if err != nil {
		return nil, err
	}
	record, err := s.moduleInstalledRecord(application)
	if err != nil {
		return nil, err
	}
	if record["version"] != core.IntegrityKernelAppVersion {
		return nil, errors.New("请先通过签名应用商店更新对应防篡改应用至 1.5.0；旧版未获得内核权限")
	}
	installed, ok := record["installed_at"].(string)
	if !ok {
		return nil, errors.New("原应用安装时间身份缺失")
	}
	if _, err = time.Parse(time.RFC3339Nano, installed); err != nil {
		return nil, errors.New("原应用安装身份无效")
	}
	return record, nil
}

func (s *Service) integrityKernelAuthority(ctx context.Context, request core.IntegrityKernelRequest) error {
	guard, close, err := s.integrityKernelAuthorityGuard(ctx, request)
	if err != nil {
		return err
	}
	defer close()
	return guard()
}

// Keep a single read-only database connection pinned for a large operation.
// Each mutation still rechecks current authority, app identity and database
// inode; no long read transaction delays permission changes or Core writes.
func (s *Service) integrityKernelAuthorityGuard(ctx context.Context, request core.IntegrityKernelRequest) (func() error, func(), error) {
	application := core.IntegrityKernelRequestApplication(request)
	if application == "" {
		return nil, nil, errors.New("原内核操作应用身份无效")
	}
	if os.Geteuid() != 0 || s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" || s.Config.SitesDir != "/srv/panel/sites" || upgradeguard.Blocked() {
		return nil, nil, errors.New("内核保护仅在实际受管 Linux 执行器环境执行")
	}
	installed, err := s.integrityKernelInstalled(application)
	if err != nil {
		return nil, nil, err
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return nil, nil, err
	}
	close := func() { reader.db.Close() }
	guard := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if upgradeguard.Blocked() || !reader.current() {
			return errors.New("原数据库身份或程序升级状态变化，停止内核操作")
		}
		current, err := s.integrityKernelInstalled(application)
		if err != nil || current["installed_at"] != installed["installed_at"] {
			return errors.New("原应用安装身份变化，停止内核操作")
		}
		if err = (&core.Store{DB: reader.db}).ValidateIntegrityKernelAuthority(ctx, request); err != nil {
			return err
		}
		if !reader.current() {
			return errors.New("授权核对期间原面板数据库变化")
		}
		return nil
	}
	if err = guard(); err != nil {
		close()
		return nil, nil, err
	}
	return guard, close, nil
}

func (s *Service) integrityKernelReadOperation(id string) (core.IntegrityKernelOperation, error) {
	out := core.IntegrityKernelOperation{State: "queued"}
	d, err := s.integrityKernelOperationDirectory(id)
	if err != nil {
		return out, err
	}
	defer d.Close()
	if err = integrityKernelValidateNames(d); err != nil {
		return out, err
	}
	closure, closureErr := integrityKernelReadClosure(d)
	if closureErr != nil && !errors.Is(closureErr, os.ErrNotExist) {
		return out, closureErr
	}
	raw, err := integrityKernelRead(d, "request.json", 8192)
	if errors.Is(err, os.ErrNotExist) && closure != nil {
		if closure.Request.ID != id || closure.OriginalRequestSHA != "" || integrityKernelNoNativeEvidence(d) != nil {
			return out, errors.New("原未受理封存见证无效")
		}
		return out, errIntegrityKernelSealed
	}
	if err != nil || integrityKernelJSON(raw, &out.Request) != nil || core.ValidateIntegrityKernelRequest(out.Request) != nil || out.Request.ID != id {
		return out, errors.New("内核保护原请求损坏或身份无效，未重放")
	}
	out.Revision = out.Request.Input.ExpectedRevision + 1
	out.RequestSHA = core.IntegrityKernelRequestSHA(out.Request)
	if closure != nil {
		if err = integrityKernelNoNativeEvidence(d); err != nil {
			return out, err
		}
		return integrityKernelClosureOperation(*closure, out.Request)
	}
	raw, err = integrityKernelRead(d, "result.json", 8192)
	if err == nil {
		var result core.IntegrityKernelOperation
		if integrityKernelJSON(raw, &result) != nil || !reflect.DeepEqual(result.Request, out.Request) || !core.ValidIntegrityKernelOperation(result) || result.State != "succeeded" && result.State != "declined" && result.State != "needs-attention" {
			return out, errors.New("内核保护原结果不能核对")
		}
		if result.State == "succeeded" {
			if result.Completed != result.Files+result.Directories || result.Directories < 1 || !core.ValidID(result.EnableOperation) || !phpValidSHA(result.PlanSHA) {
				return out, errors.New("原成功结果缺少完整对象见证")
			}
			for _, name := range []string{"started.json", "plan.json", "progress.jsonl"} {
				info, e := d.Lstat(name)
				if e != nil || !moduleRecordInfo(info, false, false) || info.Size() < 1 || info.Size() > integrityKernelRecordBytes {
					return out, errors.New("原成功任务的独立记录缺失或身份异常")
				}
			}
		}
		return result, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	raw, err = integrityKernelRead(d, "started.json", 8192)
	if errors.Is(err, os.ErrNotExist) {
		for _, name := range []string{"plan.json", "progress.jsonl"} {
			if _, e := d.Lstat(name); !errors.Is(e, os.ErrNotExist) {
				return out, errors.New("未开始任务存在原生副作用证据，停止自动执行")
			}
		}
		return out, nil
	}
	var started integrityKernelStarted
	if err != nil || integrityKernelJSON(raw, &started) != nil || started.Format != 1 || started.ID != id || started.RequestSHA != integrityKernelDigest(out.Request) || started.InstalledAt == "" {
		return out, errors.New("内核保护原开始记录不能核对")
	}
	out.State = "needs-attention"
	out.Error = "原任务已开始但最终结果未确认；请核对原记录，禁止自动重跑"
	if _, running := s.integrityKernelRunning.Load(id); running {
		out.State = "running"
		out.Error = ""
	}
	if raw, err = integrityKernelRead(d, "plan.json", integrityKernelRecordBytes); err == nil {
		var plan integrityKernelPlan
		if integrityKernelJSON(raw, &plan) != nil || validateIntegrityKernelPlan(plan) != nil || plan.SiteID != out.Request.Input.SiteID || integrityKernelPlanApplication(plan) != core.IntegrityKernelRequestApplication(out.Request) {
			return out, errors.New("内核保护原计划无效")
		}
		out.PlanSHA = integrityKernelDigest(plan)
		out.EnableOperation = plan.OperationID
		for _, target := range plan.Targets {
			if target.Directory {
				out.Directories++
			} else {
				out.Files++
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	return out, nil
}

func (s *Service) integrityKernelOperations() ([]core.IntegrityKernelOperation, error) {
	ids, err := s.integrityKernelOperationIDs()
	if err != nil {
		return nil, err
	}
	rows := make([]core.IntegrityKernelOperation, 0, len(ids))
	for _, id := range ids {
		row, e := s.integrityKernelReadOperation(id)
		if errors.Is(e, errIntegrityKernelSealed) {
			continue
		}
		if e != nil {
			return nil, e
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Request.Input.SiteID == rows[j].Request.Input.SiteID {
			return rows[i].Revision < rows[j].Revision
		}
		return rows[i].Request.Input.SiteID < rows[j].Request.Input.SiteID
	})
	previous := map[string]int64{}
	previousRows := map[string]core.IntegrityKernelOperation{}
	for _, row := range rows {
		site := row.Request.Input.SiteID
		if row.Revision != previous[site]+1 {
			return nil, errors.New("内核保护原修订链缺失、重复或分叉，未修改现场")
		}
		if row.Request.Action == "release" {
			prior, ok := previousRows[site]
			if !ok || row.Request.Input.SourceOperation != prior.Request.ID || row.Request.Input.SourceSHA != core.IntegrityKernelRequestSHA(prior.Request) || core.IntegrityKernelRequestApplication(row.Request) != core.IntegrityKernelRequestApplication(prior.Request) {
				return nil, errors.New("内核保护原解除来源链缺失或被改变")
			}
		}
		previous[site] = row.Revision
		previousRows[site] = row
	}
	return rows, nil
}

// Only metadata publication is serialized. The original inode walk, hashes,
// authority checks and ioctls run outside this lock. Callers already holding
// mu use integrityKernelOperations directly, without taking it twice.
func (s *Service) integrityKernelOperationSnapshot() ([]core.IntegrityKernelOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.integrityKernelOperations()
}

func integrityKernelLatest(rows []core.IntegrityKernelOperation, site string) *core.IntegrityKernelOperation {
	var latest *core.IntegrityKernelOperation
	for i := range rows {
		if rows[i].Request.Input.SiteID == site && (latest == nil || rows[i].Revision > latest.Revision) {
			latest = &rows[i]
		}
	}
	return latest
}

func (s *Service) integrityKernelSourcePlan(rows []core.IntegrityKernelOperation, latest core.IntegrityKernelOperation) (integrityKernelPlan, error) {
	byID := map[string]core.IntegrityKernelOperation{}
	for _, row := range rows {
		byID[row.Request.ID] = row
	}
	current := latest
	for depth := 0; depth < integrityKernelRecords; depth++ {
		if current.Request.Action == "enable" {
			d, err := s.integrityKernelOperationDirectory(current.Request.ID)
			if err != nil {
				return integrityKernelPlan{}, err
			}
			defer d.Close()
			raw, err := integrityKernelRead(d, "plan.json", integrityKernelRecordBytes)
			var plan integrityKernelPlan
			if err != nil || integrityKernelJSON(raw, &plan) != nil || validateIntegrityKernelPlan(plan) != nil || plan.OperationID != current.Request.ID || plan.SiteID != current.Request.Input.SiteID || plan.BaselineSHA != current.Request.Input.BaselineSHA || integrityKernelPlanApplication(plan) != core.IntegrityKernelRequestApplication(current.Request) {
				return plan, errors.New("原启用计划缺失或无法核对；未猜测原路径、标记或所有者")
			}
			if current.PlanSHA != "" && current.PlanSHA != integrityKernelDigest(plan) {
				return plan, errors.New("原启用计划完整摘要已变化")
			}
			progress, e := readIntegrityKernelProgress(d, current.Request, plan)
			if e != nil {
				return plan, e
			}
			if current.State == "succeeded" {
				completed := 0
				for _, row := range progress {
					if row.Stage == "verified" {
						completed++
					}
				}
				if completed != len(plan.Targets) {
					return plan, errors.New("原成功任务进度不完整")
				}
			}
			return plan, nil
		}
		previous, ok := byID[current.Request.Input.SourceOperation]
		if !ok || previous.Request.Input.SiteID != latest.Request.Input.SiteID || previous.Revision+1 != current.Revision || integrityKernelDigest(previous.Request) != current.Request.Input.SourceSHA || core.IntegrityKernelRequestApplication(previous.Request) != core.IntegrityKernelRequestApplication(current.Request) {
			return integrityKernelPlan{}, errors.New("原解除任务来源链不能核对")
		}
		current = previous
	}
	return integrityKernelPlan{}, errors.New("原任务来源链超过完整预算")
}

func (s *Service) integrityKernelSubmit(ctx context.Context, request core.IntegrityKernelRequest) (core.IntegrityKernelOperation, error) {
	if err := core.ValidateIntegrityKernelRequest(request); err != nil {
		return core.IntegrityKernelOperation{}, err
	}
	application := core.IntegrityKernelRequestApplication(request)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Existing identity wins before revision checks: observing the exact
	// original request never starts a new operation or overwrites its result.
	if original, err := s.integrityKernelReadOperation(request.ID); err == nil {
		a, b := original.Request, request
		a.CreatedAt = ""
		b.CreatedAt = ""
		if !reflect.DeepEqual(a, b) {
			return original, errors.New("原提交键已绑定不同操作者、授权、应用或输入，未重新执行")
		}
		return original, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.IntegrityKernelOperation{}, err
	}
	if err := s.integrityKernelAuthority(ctx, request); err != nil {
		return core.IntegrityKernelOperation{}, err
	}
	if err := s.moduleRetrospectivePreflight(application); err != nil {
		return core.IntegrityKernelOperation{}, err
	}
	rows, err := s.integrityKernelOperations()
	if err != nil {
		return core.IntegrityKernelOperation{}, err
	}
	if len(rows) >= integrityKernelRecords {
		return core.IntegrityKernelOperation{}, errors.New("内核保护原任务保留库已满，未删除历史或新增任务")
	}
	if err = s.integrityKernelCapacity(rows, request.Action); err != nil {
		return core.IntegrityKernelOperation{}, err
	}
	latest := integrityKernelLatest(rows, request.Input.SiteID)
	revision := int64(0)
	if latest != nil {
		revision = latest.Revision
	}
	if request.Input.ExpectedRevision != revision {
		return core.IntegrityKernelOperation{}, errors.New("网站内核保护修订已改变，请核对最新原任务")
	}
	if latest != nil {
		_, running := s.integrityKernelRunning.Load(latest.Request.ID)
		if running || latest.State == "queued" {
			return core.IntegrityKernelOperation{}, errors.New("原任务仍在排队或执行，未创建重叠操作")
		}
	}
	if request.Action == "enable" {
		if latest != nil && !(latest.State == "succeeded" && latest.Request.Action == "release" || latest.State == "declined" || latest.State == "cancelled" && latest.Request.Action == "enable") {
			return core.IntegrityKernelOperation{}, errors.New("原保护仍启用或结果待核对；先选择原任务解除，不能覆盖基线或重新启用")
		}
		baseline, e := s.readIntegrityBaseline(application, request.Input.SiteID)
		if e != nil || baseline.Signature != request.Input.BaselineSHA {
			return core.IntegrityKernelOperation{}, errors.New("当前原签名基线不能核对")
		}
	} else {
		if latest != nil && core.IntegrityKernelRequestApplication(latest.Request) != application {
			return core.IntegrityKernelOperation{}, errors.New("该保护属于另一防篡改应用；请从原应用和原任务解除，不能接管或清除其标记")
		}
		if latest == nil || latest.Request.ID != request.Input.SourceOperation || integrityKernelDigest(latest.Request) != request.Input.SourceSHA {
			return core.IntegrityKernelOperation{}, errors.New("请选择最新原任务和精确摘要解除保护")
		}
		if latest.State == "succeeded" && latest.Request.Action == "release" || latest.State == "declined" || latest.State == "cancelled" && latest.Request.Action == "enable" {
			return core.IntegrityKernelOperation{}, errors.New("原任务未留下待解除的保护；没有重复执行")
		}
		if _, err = s.integrityKernelSourcePlan(rows, *latest); err != nil {
			return core.IntegrityKernelOperation{}, err
		}
	}
	d, err := s.integrityKernelStore(true)
	if err != nil {
		return core.IntegrityKernelOperation{}, err
	}
	if err = d.Mkdir(request.ID, 0700); err != nil {
		d.Close()
		return core.IntegrityKernelOperation{}, err
	}
	parent, e := d.Open(".")
	if e != nil {
		d.Close()
		return core.IntegrityKernelOperation{}, e
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		d.Close()
		return core.IntegrityKernelOperation{}, err
	}
	d, err = integrityKernelChild(d, request.ID)
	if err != nil {
		return core.IntegrityKernelOperation{}, err
	}
	defer d.Close()
	if err = integrityKernelCreate(d, "request.json", request); err != nil {
		return core.IntegrityKernelOperation{}, fmt.Errorf("原任务可能已接收，保留提交键核对：%w", err)
	}
	if s.integrityKernelWake != nil {
		select {
		case s.integrityKernelWake <- struct{}{}:
		default:
		}
	}
	return core.IntegrityKernelOperation{Request: request, RequestSHA: core.IntegrityKernelRequestSHA(request), Revision: revision + 1, State: "queued"}, nil
}

func (s *Service) integrityKernelRoutes(m *http.ServeMux) {
	s.integrityKernelAdmissionRoutes(m)
	for _, route := range core.IntegrityKernelApplicationRoutes() {
		s.integrityKernelApplicationRoutes(m, route)
	}
}

func (s *Service) integrityKernelApplicationRoutes(m *http.ServeMux, route core.IntegrityKernelApplicationRoute) {
	m.HandleFunc("GET "+route.Executor, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if len(query) != 1 || len(query["site_id"]) != 1 || !core.ValidID(query.Get("site_id")) {
			respond(w, 400, map[string]string{"error": "内核保护状态须明确选择网站"})
			return
		}
		out, err := s.integrityKernelStatus(r.Context(), query.Get("site_id"), route.Application)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST "+route.Executor+"/operations/{operation}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		var request core.IntegrityKernelRequest
		if err != nil || integrityKernelJSON(raw, &request) != nil || request.ID != r.PathValue("operation") || core.ValidateIntegrityKernelRequest(request) != nil || core.IntegrityKernelRequestApplication(request) != route.Application {
			respond(w, 400, map[string]string{"error": "内核保护原请求无效"})
			return
		}
		out, err := s.integrityKernelSubmit(r.Context(), request)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 202, out)
	})
}

func (s *Service) runIntegrityKernelWorker(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		rows, err := s.integrityKernelOperationSnapshot()
		if err == nil {
			for _, row := range rows {
				if ctx.Err() != nil {
					return
				}
				if row.State != "queued" {
					continue
				}
				s.integrityKernelExecute(ctx, row.Request)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-s.integrityKernelWake:
		case <-ticker.C:
		}
	}
}

func integrityKernelBoundedError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ToValidUTF8(err.Error(), "?")
	if len(text) > 1900 {
		text = text[:1900]
		text = strings.ToValidUTF8(text, "?")
	}
	return text
}
