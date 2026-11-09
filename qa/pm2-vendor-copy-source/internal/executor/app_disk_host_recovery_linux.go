//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/diskjob"
)

func (s *Service) diskHostRecover(ctx context.Context, in diskjob.RecoveryRequest) (diskjob.RecoveryAck, error) {
	ack := diskjob.RecoveryAck{Format: 1, JobID: in.Request.JobID, RequestSHA: diskjob.RequestSHA(in.Request), State: "cancel_requested"}
	if !s.diskHostFixedEnvironment() {
		return ack, errDiskHostWorker
	}
	s.diskHostMu.Lock()
	defer s.diskHostMu.Unlock()
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return ack, err
	}
	defer reader.db.Close()
	guard := func() error {
		if ctx.Err() != nil || !reader.current() || !s.diskHostFixedEnvironment() {
			return errDiskHostWorker
		}
		return (&core.Store{DB: reader.db}).ValidateHostDiskRecovery(ctx, in)
	}
	if err := guard(); err != nil {
		return ack, err
	}
	lease, err := diskjob.InstanceLease(false)
	if err != nil {
		return ack, err
	}
	defer lease.Close()
	j, err := diskjob.OpenRootJob(in.Request.JobID)
	if errors.Is(err, os.ErrNotExist) {
		// A fresh cancellation fence, never a launch or a repair of an existing
		// empty/partial job directory. Late dispatch becomes observation-only.
		j, _, err = diskjob.PublishRootRequest(in.Request)
	}
	if err != nil {
		return ack, err
	}
	defer j.Close()
	request, err := j.Request()
	if err != nil || request != in.Request {
		return ack, errDiskHostWorker
	}
	if !j.AdmissionBlocked() {
		raw, err := j.Read("dispatch.json")
		if err == nil {
			d, err := diskjob.DecodeDispatch(raw, in.Request)
			if err != nil {
				return ack, err
			}
			if raw, err := j.Read("started.json"); err == nil {
				if started, err := diskjob.DecodeStarted(raw, d, in.Request); err == nil {
					native := diskjob.ObserveNative(in.Request, d, started)
					if native.Process == "alive" && native.Scope == "busy" {
						if err := guard(); err != nil {
							return ack, err
						}
						ack.SignalRequested, err = diskjob.SignalOriginal(in.Request, d, started)
						if err != nil {
							return ack, err
						}
						return ack, guard()
					}
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return ack, err
		}
	}
	if err := guard(); err != nil {
		return ack, err
	}
	// A confirmed cancellation can precede the original launcher's exit.
	// Observe its leases within this request's existing deadline, rechecking
	// current authority throughout. Seal only once; never retry a write whose
	// outcome is unknown, and never start or replay a worker while waiting.
	if err := j.WaitForAdmissionIdle(ctx, func() bool { return guard() == nil }); err != nil {
		return ack, err
	}
	closed, err := j.SealClosure(in.Request)
	if err != nil {
		return ack, err
	}
	if err := guard(); err != nil {
		return ack, err
	}
	ack.State = closed.State
	ack.Closure = &closed
	return ack, diskjob.ValidateRecoveryAck(ack, in.Request)
}

func (s *Service) diskHostRecoveryRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/disk-host-jobs/recover", func(w http.ResponseWriter, r *http.Request) {
		var raw json.RawMessage
		if !readJSON(w, r, &raw) {
			return
		}
		in, err := diskjob.DecodeRecoveryRequest(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": "原任务收尾请求无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		ack, err := s.diskHostRecover(ctx, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原任务尚未核对停止或原证据不能安全封闭；未重放、覆盖或假报结束"})
			return
		}
		respond(w, 202, ack)
	})
}
