//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type integrityKernelProgress struct {
	Sequence    int    `json:"sequence"`
	OperationID string `json:"operation_id"`
	PlanSHA     string `json:"plan_sha"`
	PreviousSHA string `json:"previous_sha"`
	Index       int    `json:"index"`
	Stage       string `json:"stage"`
	Flags       int    `json:"flags"`
	Time        string `json:"time"`
}

type integrityKernelJournal struct {
	file                  *os.File
	directory             *modulePrivateDirectory
	id, planSHA, previous string
	sequence              int
	bytes                 int64
}

func newIntegrityKernelJournal(d *modulePrivateDirectory, id, planSHA string) (*integrityKernelJournal, error) {
	f, err := d.OpenFile("progress.jsonl", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	j := &integrityKernelJournal{file: f, directory: d, id: id, planSHA: planSHA}
	if err = j.append(-1, "prepared", 0); err != nil {
		f.Close()
		return nil, err
	}
	parent, err := d.Open(".")
	if err != nil {
		f.Close()
		return nil, err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		f.Close()
		return nil, err
	}
	return j, nil
}

func (j *integrityKernelJournal) append(index int, stage string, flags int) error {
	if !j.directory.current() {
		return errors.New("原任务私有目录发生变化，停止内核操作")
	}
	line := integrityKernelProgress{Sequence: j.sequence + 1, OperationID: j.id, PlanSHA: j.planSHA, PreviousSHA: j.previous, Index: index, Stage: stage, Flags: flags, Time: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(line)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if j.bytes+int64(len(raw)) > integrityKernelRecordBytes || j.sequence > 2*integrityKernelTargets {
		return errors.New("原任务进度超过完整预算，现场保留")
	}
	before, err := j.file.Stat()
	visible, e := j.directory.Lstat("progress.jsonl")
	if err != nil || e != nil || !os.SameFile(before, visible) || !moduleRecordInfo(before, false, false) || !moduleRecordInfo(visible, false, false) || before.Size() != j.bytes {
		return errors.New("原任务进度文件被替换、截断或权限变化")
	}
	n, err := j.file.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	if err = j.file.Sync(); err != nil {
		return err
	}
	j.bytes += int64(n)
	j.sequence = line.Sequence
	j.previous = integrityKernelDigest(line)
	if !j.directory.current() {
		return errors.New("原任务进度可能已保存，但目录变化；停止内核操作")
	}
	return nil
}

func readIntegrityKernelProgress(d *modulePrivateDirectory, request core.IntegrityKernelRequest, plan integrityKernelPlan) ([]integrityKernelProgress, error) {
	raw, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("原启用进度缺失，不能核对标记归属；未猜测或解除")
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("原进度存在未完整落盘记录，未猜测执行结果")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 8192)
	rows := []integrityKernelProgress{}
	previous := ""
	planSHA := integrityKernelDigest(plan)
	for scanner.Scan() {
		var row integrityKernelProgress
		if len(rows) > 2*integrityKernelTargets || integrityKernelJSON(scanner.Bytes(), &row) != nil || row.Sequence != len(rows)+1 || row.OperationID != request.ID || row.PlanSHA != planSHA || row.PreviousSHA != previous || row.Flags < 0 {
			return nil, errors.New("原进度序号、摘要或身份链无效")
		}
		if _, e := time.Parse(time.RFC3339Nano, row.Time); e != nil {
			return nil, errors.New("原进度时间无效")
		}
		if len(rows) == 0 {
			if row.Index != -1 || row.Stage != "prepared" || row.Flags != 0 {
				return nil, errors.New("原进度准备记录缺失")
			}
		} else if row.Index < 0 || row.Index >= len(plan.Targets) || row.Stage != "intent" && row.Stage != "verified" && row.Stage != "not-owned" {
			return nil, errors.New("原进度对象或阶段无效")
		}
		rows = append(rows, row)
		previous = integrityKernelDigest(row)
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	// The original enable visits each target once, parent first. A partial
	// final intent is retained, but cannot become a second enable operation.
	if len(rows) == 0 {
		return nil, errors.New("原任务准备记录缺失")
	}
	if request.Action == "enable" {
		index, pending := 0, false
		for _, row := range rows[1:] {
			if row.Index != index || index >= len(plan.Targets) {
				return nil, errors.New("原启用对象顺序重复或缺失")
			}
			target := plan.Targets[index]
			own := target.Original.Flags&integrityImmutableFlag == 0
			switch row.Stage {
			case "intent":
				if !own || pending || row.Flags != target.Original.Flags {
					return nil, errors.New("原启用意图不能核对")
				}
				pending = true
			case "verified":
				if own && !pending || row.Flags != target.Original.Flags|integrityImmutableFlag {
					return nil, errors.New("原启用校验不能核对")
				}
				index++
				pending = false
			default:
				return nil, errors.New("原启用进度不能借用解除阶段")
			}
		}
	}
	return rows, nil
}

func (s *Service) integrityKernelVerify(ctx context.Context, plan integrityKernelPlan, hashContent bool) error {
	site, public, err := s.integrityKernelOpenPlan(plan)
	if err != nil {
		return err
	}
	defer site.Close()
	defer public.Close()
	byPath := map[string]integrityKernelTarget{}
	for _, target := range plan.Targets {
		byPath[target.Path] = target
	}
	seen := 0
	err = fs.WalkDir(site.public.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if integrityKernelExcluded(path, plan.Excludes) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return errors.New("排除目录类型变化")
		}
		target, ok := byPath[path]
		if !ok || target.Directory != entry.IsDir() {
			return errors.New("保护范围出现新增或替换路径")
		}
		f, e := openIntegrityFlagTarget(public, path, target.Directory)
		if e != nil {
			return e
		}
		defer f.Close()
		state, e := readIntegrityInodeFlags(f, target.Directory)
		if e != nil {
			return e
		}
		if state.Identity != target.Original.Identity || state.Flags != target.Original.Flags|integrityImmutableFlag {
			return errors.New("实际 inode、原元数据或内核保护标记不匹配：" + path)
		}
		if hashContent && !target.Directory {
			sha, e := integrityKernelFileSHA(ctx, f, state.Identity)
			if e != nil {
				return e
			}
			if sha != target.SHA {
				return errors.New("启用后完整内容摘要与原签名基线不符：" + path)
			}
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(plan.Targets) {
		return errors.New("保护对象缺失，未宣称完整启用")
	}
	// Reopen the actual named site, rather than validating only detached FDs.
	fresh, root, e := s.integrityKernelOpenPlan(plan)
	if e != nil {
		return e
	}
	root.Close()
	fresh.Close()
	return nil
}

func (s *Service) integrityKernelApply(ctx context.Context, request core.IntegrityKernelRequest, plan integrityKernelPlan, j *integrityKernelJournal, completed *int, attempted *bool, authority func() error) error {
	if authority == nil {
		return errors.New("缺少原内核任务授权见证")
	}
	site, public, err := s.integrityKernelOpenPlan(plan)
	if err != nil {
		return err
	}
	defer site.Close()
	defer public.Close()
	for index, target := range plan.Targets {
		if err = ctx.Err(); err != nil {
			return err
		}
		if index%256 == 0 {
			if err = authority(); err != nil {
				return err
			}
		}
		f, e := openIntegrityFlagTarget(public, target.Path, target.Directory)
		if e != nil {
			return e
		}
		state, e := readIntegrityInodeFlags(f, target.Directory)
		if e != nil || state != target.Original {
			f.Close()
			return errors.New("启用前原对象或标记已变化：" + target.Path)
		}
		if state.Flags&integrityImmutableFlag == 0 {
			if e = authority(); e != nil {
				f.Close()
				return e
			}
			if e = j.append(index, "intent", state.Flags); e != nil {
				f.Close()
				return e
			}
			if e = authority(); e != nil {
				f.Close()
				return e
			}
			*attempted = true
			state, e = setIntegrityInodeImmutable(f, target.Directory, state, true)
			if e != nil {
				f.Close()
				return e
			}
		}
		f.Close()
		if e = j.append(index, "verified", state.Flags); e != nil {
			return e
		}
		*completed++
	}
	if err = authority(); err != nil {
		return err
	}
	baseline, err := s.readIntegrityBaseline(integrityKernelModule, plan.SiteID)
	if err != nil || baseline.Signature != plan.BaselineSHA {
		return errors.New("原签名基线在启用期间变化，未宣称完整启用")
	}
	return s.integrityKernelVerify(ctx, plan, true)
}

func integrityKernelSameReleaseInode(a, b integrityInodeIdentity) bool {
	return a.Device == b.Device && a.Inode == b.Inode && a.UID == b.UID && a.GID == b.GID && a.Mode == b.Mode && a.Links == b.Links
}

func (s *Service) integrityKernelRelease(ctx context.Context, request core.IntegrityKernelRequest, plan integrityKernelPlan, j *integrityKernelJournal, completed *int, attempted *bool, authority func() error) error {
	if authority == nil {
		return errors.New("缺少原解除任务授权见证")
	}
	original, err := s.integrityKernelOperationDirectory(plan.OperationID)
	if err != nil {
		return err
	}
	defer original.Close()
	source, err := s.integrityKernelReadOperation(plan.OperationID)
	if err != nil {
		return err
	}
	progress, err := readIntegrityKernelProgress(original, source.Request, plan)
	if err != nil {
		return err
	}
	intents := map[int]bool{}
	for _, row := range progress {
		if row.Stage == "intent" {
			intents[row.Index] = true
		}
	}
	site, public, err := s.integrityKernelOpenPlanMode(plan, true)
	if err != nil {
		return err
	}
	defer site.Close()
	defer public.Close()
	// Release files, then child directories, then public root. Only original
	// enable intents can own a bit; pre-existing flags are never cleared.
	for index := len(plan.Targets) - 1; index >= 0; index-- {
		if err = ctx.Err(); err != nil {
			return err
		}
		if index%256 == 0 {
			if err = authority(); err != nil {
				return err
			}
		}
		target := plan.Targets[index]
		if !intents[index] {
			if err = j.append(index, "not-owned", target.Original.Flags); err != nil {
				return err
			}
			*completed++
			continue
		}
		if target.Original.Flags&integrityImmutableFlag != 0 {
			return errors.New("原有保护不能被本应用认领或移除")
		}
		f, e := openIntegrityFlagTarget(public, target.Path, target.Directory)
		if e != nil {
			return e
		}
		state, e := readIntegrityInodeFlags(f, target.Directory)
		sameIdentity := integrityKernelSameReleaseInode(state.Identity, target.Original.Identity)
		if target.Directory && state.Flags == target.Original.Flags && state.Flags&integrityImmutableFlag == 0 {
			sameIdentity = integrityKernelSameDirectoryIdentity(state.Identity, target.Original.Identity)
		}
		if e != nil || !sameIdentity || state.Flags != target.Original.Flags && state.Flags != target.Original.Flags|integrityImmutableFlag {
			f.Close()
			return errors.New("解除前原 inode、数字所有者或其他标记已变化：" + target.Path)
		}
		if state.Flags&integrityImmutableFlag != 0 {
			if e = authority(); e != nil {
				f.Close()
				return e
			}
			if state.Identity != target.Original.Identity {
				f.Close()
				return errors.New("仍保护的原对象元数据发生变化，未猜测解除：" + target.Path)
			}
			if e = j.append(index, "intent", state.Flags); e != nil {
				f.Close()
				return e
			}
			if e = authority(); e != nil {
				f.Close()
				return e
			}
			*attempted = true
			state, e = setIntegrityInodeImmutable(f, target.Directory, state, false)
			if e != nil {
				f.Close()
				return e
			}
		}
		f.Close()
		if e = j.append(index, "verified", state.Flags); e != nil {
			return e
		}
		*completed++
	}
	return nil
}

func (s *Service) integrityKernelExecute(parent context.Context, request core.IntegrityKernelRequest) {
	if _, loaded := s.integrityKernelRunning.LoadOrStore(request.ID, true); loaded {
		return
	}
	defer s.integrityKernelRunning.Delete(request.ID)
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()
	s.mu.Lock()
	original, err := s.integrityKernelReadOperation(request.ID)
	if err != nil || original.State != "queued" {
		s.mu.Unlock()
		return
	}
	d, err := s.integrityKernelOperationDirectory(request.ID)
	if err != nil {
		s.mu.Unlock()
		return
	}
	defer d.Close()
	installed, err := s.integrityKernelInstalled()
	var authority func() error
	var closeAuthority func()
	if err == nil {
		authority, closeAuthority, err = s.integrityKernelAuthorityGuard(ctx, request)
		if closeAuthority != nil {
			defer closeAuthority()
		}
	}
	if err == nil {
		err = s.moduleRetrospectivePreflight(integrityKernelModule)
	}
	if err == nil {
		err = integrityKernelCreate(d, "started.json", integrityKernelStarted{Format: 1, ID: request.ID, RequestSHA: integrityKernelDigest(request), InstalledAt: installed["installed_at"].(string), StartedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		// A failed exclusive start can be another original worker. Never
		// overwrite its pending outcome with our own error receipt.
		if err != nil {
			s.mu.Unlock()
			return
		}
	}
	s.mu.Unlock()
	plan := integrityKernelPlan{}
	attempted, completed := false, 0
	if err == nil {
		if request.Action == "enable" {
			plan, err = s.integrityKernelPrepare(ctx, request)
		} else {
			var rows []core.IntegrityKernelOperation
			rows, err = s.integrityKernelOperations()
			if err == nil {
				source := integrityKernelLatest(rows, request.Input.SiteID)
				if source == nil || source.Request.ID != request.ID {
					err = errors.New("原解除任务不再是最新修订")
				} else {
					for _, row := range rows {
						if row.Request.ID == request.Input.SourceOperation {
							plan, err = s.integrityKernelSourcePlan(rows, row)
							break
						}
					}
					if plan.OperationID == "" && err == nil {
						err = errors.New("原启用来源计划不存在")
					}
				}
			}
		}
	}
	if err == nil {
		err = integrityKernelCreate(d, "plan.json", plan)
	}
	var journal *integrityKernelJournal
	if err == nil {
		journal, err = newIntegrityKernelJournal(d, request.ID, integrityKernelDigest(plan))
	}
	if journal != nil {
		defer journal.file.Close()
	}
	if err == nil {
		if request.Action == "enable" {
			err = s.integrityKernelApply(ctx, request, plan, journal, &completed, &attempted, authority)
		} else {
			err = s.integrityKernelRelease(ctx, request, plan, journal, &completed, &attempted, authority)
		}
	}
	out := core.IntegrityKernelOperation{Request: request, RequestSHA: core.IntegrityKernelRequestSHA(request), Revision: request.Input.ExpectedRevision + 1, State: "succeeded", Completed: completed, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if plan.OperationID != "" && validateIntegrityKernelPlan(plan) == nil {
		out.PlanSHA = integrityKernelDigest(plan)
		out.EnableOperation = plan.OperationID
		for _, target := range plan.Targets {
			if target.Directory {
				out.Directories++
			} else {
				out.Files++
			}
		}
	}
	if err != nil {
		out.State = "needs-attention"
		if request.Action == "enable" && !attempted {
			out.State = "declined"
		}
		out.Error = integrityKernelBoundedError(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if historyErr := s.appendModuleEvent(integrityKernelModule, "kernel-"+request.Action, "durable-worker", core.AppModuleInput{SiteID: request.Input.SiteID}, out, err); historyErr != nil {
		out.State = "needs-attention"
		if request.Action == "enable" && !attempted {
			out.State = "declined"
		}
		out.Error = integrityKernelBoundedError(fmt.Errorf("原内核操作结果需核对，历史记录保存失败：%w", historyErr))
	}
	if err = integrityKernelCreate(d, "result.json", out); err != nil {
		log.Printf("integrity_kernel_result_unknown operation=%s", request.ID)
	}
}
