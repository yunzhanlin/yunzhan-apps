//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"time"

	"local/panel/internal/core"
)

var errIntegrityKernelSealed = errors.New("原未开始提交已经独立封存；迟到请求不会被派发，不会自动重新执行")

func integrityKernelReadClosure(d *modulePrivateDirectory) (*core.IntegrityKernelClosure, error) {
	raw, err := integrityKernelRead(d, "closure.json", 16384)
	if err != nil {
		return nil, err
	}
	var closure core.IntegrityKernelClosure
	if integrityKernelJSON(raw, &closure) != nil || !core.ValidIntegrityKernelClosure(closure) {
		return nil, errors.New("原未开始提交封存记录损坏，未忽略或覆盖")
	}
	return &closure, nil
}

func integrityKernelNoNativeEvidence(d *modulePrivateDirectory) error {
	for _, name := range []string{"started.json", "plan.json", "progress.jsonl", "result.json"} {
		if _, err := d.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("原任务已开始或存在原生结果证据；不能借封存改写原结果")
		}
	}
	if !d.current() {
		return errors.New("核对未开始证据期间父目录变化")
	}
	return nil
}

func integrityKernelClosureOperation(closure core.IntegrityKernelClosure, request core.IntegrityKernelRequest) (core.IntegrityKernelOperation, error) {
	if closure.Request.ID != request.ID || closure.Request.ActorID != request.ActorID || closure.Request.Action != request.Action || core.IntegrityKernelRequestApplication(closure.Request) != core.IntegrityKernelRequestApplication(request) || !reflect.DeepEqual(closure.Request.Input, request.Input) || closure.OriginalRequestSHA != core.IntegrityKernelRequestSHA(request) {
		return core.IntegrityKernelOperation{}, errors.New("原排队请求与独立封存见证不符")
	}
	return core.IntegrityKernelOperation{Request: request, RequestSHA: core.IntegrityKernelRequestSHA(request), State: "cancelled", Revision: request.Input.ExpectedRevision + 1, Error: "原排队提交已独立封存，未派发内核操作；原有保护、文件和记录保留", FinishedAt: closure.SealedAt}, nil
}

func (s *Service) integrityKernelAdmission(id string) (core.IntegrityKernelAdmission, error) {
	out := core.IntegrityKernelAdmission{ID: id, State: "absent"}
	if !core.ValidID(id) {
		return out, errors.New("原提交标识无效")
	}
	op, opErr := s.integrityKernelReadOperation(id)
	if opErr == nil && op.State != "cancelled" {
		out.State = "original"
		out.Operation = &op
		return out, nil
	}
	if opErr != nil && !errors.Is(opErr, errIntegrityKernelSealed) && !errors.Is(opErr, os.ErrNotExist) {
		return out, opErr
	}
	d, err := s.integrityKernelOperationDirectory(id)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	defer d.Close()
	closure, err := integrityKernelReadClosure(d)
	if err != nil {
		return out, err
	}
	if closure.Request.ID != id || integrityKernelNoNativeEvidence(d) != nil {
		return out, errors.New("原封存不是未开始提交的完整见证")
	}
	out.State = "sealed"
	out.Closure = closure
	if opErr == nil {
		out.Operation = &op
	}
	return out, nil
}

func (s *Service) integrityKernelAdmissionSnapshot(id string) (core.IntegrityKernelAdmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.integrityKernelAdmission(id)
}

// The caller already holds mu and has just checked current authority. A
// queued worker must obtain this same lock before persisting its start. The
// exclusive closure therefore either proves no dispatch or returns the exact
// original operation; it cannot relabel a started/failed/unknown mutation.
func (s *Service) integrityKernelSealAdmission(request core.IntegrityKernelCloseRequest) (core.IntegrityKernelAdmission, error) {
	original := request.Request
	out := core.IntegrityKernelAdmission{ID: original.ID}
	if !core.ValidID(request.ID) || core.ValidateIntegrityKernelRequest(original) != nil {
		return out, errors.New("独立封存身份无效")
	}
	if existing, err := s.integrityKernelAdmission(original.ID); err == nil && existing.State == "sealed" {
		if existing.Closure.Request.ActorID != original.ActorID || existing.Closure.Request.Action != original.Action || core.IntegrityKernelRequestApplication(existing.Closure.Request) != core.IntegrityKernelRequestApplication(original) || !reflect.DeepEqual(existing.Closure.Request.Input, original.Input) {
			return out, errors.New("原提交标识已封存不同的输入或操作者")
		}
		return existing, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		// An empty private admission directory can be a pre-request crash.
		// It is inspected below, never treated as an absent native result.
		d, e := s.integrityKernelOperationDirectory(original.ID)
		if e != nil {
			return out, err
		}
		f, e := d.Open(".")
		if e != nil {
			d.Close()
			return out, err
		}
		entries, readErr := f.ReadDir(1)
		f.Close()
		current := d.current()
		d.Close()
		if len(entries) != 0 || readErr != nil && !errors.Is(readErr, io.EOF) || !current {
			return out, err
		}
	}
	var previous *core.IntegrityKernelRequest
	op, err := s.integrityKernelReadOperation(original.ID)
	if err == nil {
		if op.Request.ActorID != original.ActorID || op.Request.Action != original.Action || core.IntegrityKernelRequestApplication(op.Request) != core.IntegrityKernelRequestApplication(original) || !reflect.DeepEqual(op.Request.Input, original.Input) {
			return out, errors.New("原提交键绑定不同的输入或操作者")
		}
		if op.State != "queued" {
			out.State = "original"
			out.Operation = &op
			return out, nil
		}
		previous = &op.Request
	}
	d, dirErr := s.integrityKernelOperationDirectory(original.ID)
	if errors.Is(dirErr, os.ErrNotExist) {
		rows, e := s.integrityKernelOperations()
		if e != nil {
			return out, e
		}
		if e = s.integrityKernelCapacity(rows, "release"); e != nil {
			return out, e
		}
		ids, e := s.integrityKernelOperationIDs()
		if e != nil || len(ids) >= integrityKernelRecords {
			return out, errors.New("原提交封存容量不足，未删除原记录")
		}
		d, e = s.integrityKernelStore(true)
		if e != nil {
			return out, e
		}
		if e = d.Mkdir(original.ID, 0700); e != nil {
			d.Close()
			return out, e
		}
		parent, e := d.Open(".")
		if e != nil {
			d.Close()
			return out, e
		}
		e = parent.Sync()
		parent.Close()
		if e != nil {
			d.Close()
			return out, e
		}
		d, dirErr = integrityKernelChild(d, original.ID)
	}
	if dirErr != nil {
		return out, dirErr
	}
	defer d.Close()
	if err = integrityKernelValidateNames(d); err != nil {
		return out, err
	}
	if err = integrityKernelNoNativeEvidence(d); err != nil {
		if previous != nil {
			out.State = "original"
			out.Operation = &op
			return out, nil
		}
		return out, err
	}
	if previous == nil {
		if _, e := d.Lstat("request.json"); !errors.Is(e, os.ErrNotExist) {
			return out, errors.New("原请求记录存在但无法核对，未用封存掩盖损坏")
		}
	}
	closure := core.IntegrityKernelClosure{Format: 1, ID: request.ID, Request: original, SealedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if previous != nil {
		closure.OriginalRequestSHA = core.IntegrityKernelRequestSHA(*previous)
	}
	if err = integrityKernelCreate(d, "closure.json", closure); err != nil {
		return out, err
	}
	out.State = "sealed"
	out.Closure = &closure
	if previous != nil {
		cancelled, e := integrityKernelClosureOperation(closure, *previous)
		if e != nil {
			return out, e
		}
		out.Operation = &cancelled
	}
	return out, nil
}

func (s *Service) integrityKernelCloseAdmission(ctx context.Context, request core.IntegrityKernelCloseRequest) (core.IntegrityKernelAdmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !core.ValidID(request.ID) || core.ValidateIntegrityKernelRequest(request.Request) != nil {
		return core.IntegrityKernelAdmission{}, errors.New("原提交封存请求无效")
	}
	if err := s.integrityKernelAuthority(ctx, request.Request); err != nil {
		return core.IntegrityKernelAdmission{}, err
	}
	application := core.IntegrityKernelRequestApplication(request.Request)
	if err := s.moduleRetrospectivePreflight(application); err != nil {
		return core.IntegrityKernelAdmission{}, err
	}
	out, err := s.integrityKernelSealAdmission(request)
	if err == nil && out.State == "sealed" {
		if historyErr := s.appendModuleEvent(application, "kernel-admission-close", "manual", core.AppModuleInput{SiteID: request.Request.Input.SiteID}, out, nil); historyErr != nil {
			return out, errors.New("原未开始提交可能已封存，但摘要历史保存失败；只读核对原提交，不重新执行")
		}
	}
	return out, err
}

func (s *Service) integrityKernelAdmissionRoutes(m *http.ServeMux) {
	for _, route := range core.IntegrityKernelApplicationRoutes() {
		s.integrityKernelApplicationAdmissionRoutes(m, route)
	}
}

func (s *Service) integrityKernelApplicationAdmissionRoutes(m *http.ServeMux, route core.IntegrityKernelApplicationRoute) {
	m.HandleFunc("GET "+route.Executor+"/admissions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !core.ValidID(r.PathValue("id")) || len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "原提交核对标识无效"})
			return
		}
		out, err := s.integrityKernelAdmissionSnapshot(r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if !core.IntegrityKernelAdmissionApplicationMatches(out, route.Application) {
			respond(w, 409, map[string]string{"error": "原提交属于另一应用；没有接管、封存或改变原结果"})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST "+route.Executor+"/close-admission", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
		var request core.IntegrityKernelCloseRequest
		if err != nil || integrityKernelJSON(raw, &request) != nil || !core.ValidID(request.ID) || core.ValidateIntegrityKernelRequest(request.Request) != nil || core.IntegrityKernelRequestApplication(request.Request) != route.Application {
			respond(w, 400, map[string]string{"error": "原提交封存请求无效"})
			return
		}
		out, err := s.integrityKernelCloseAdmission(r.Context(), request)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}
