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

type diskHostCancelReceipt struct {
	Format     int    `json:"format"`
	JobID      string `json:"job_id"`
	ActorID    string `json:"actor_id"`
	RequestSHA string `json:"request_sha256"`
	At         string `json:"at"`
}

func (s *Service) diskHostCancel(ctx context.Context, in diskjob.Request) (diskjob.CancelAck, error) {
	ack := diskjob.CancelAck{Format: 1, JobID: in.JobID, RequestSHA: diskjob.RequestSHA(in)}
	if !s.diskHostFixedEnvironment() || diskjob.ValidateRequest(in) != nil {
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
		j, err := (&core.Store{DB: reader.db}).HostDiskForActor(ctx, in.JobID, in.ActorID)
		if err != nil || j.Request != in || j.State != "cancel_requested" || j.CancelState != "requested" {
			return errDiskHostWorker
		}
		return nil
	}
	if err := guard(); err != nil {
		return ack, err
	}
	j, err := diskjob.OpenRootJob(in.JobID)
	if err != nil {
		return ack, err
	}
	defer j.Close()
	request, err := j.Request()
	if err != nil || request != in {
		return ack, errDiskHostWorker
	}
	receipt := diskHostCancelReceipt{1, in.JobID, in.ActorID, diskjob.RequestSHA(in), time.Now().UTC().Format(time.RFC3339Nano)}
	if raw, err := j.Read("cancel.json"); err == nil {
		var old diskHostCancelReceipt
		if json.Unmarshal(raw, &old) != nil {
			return ack, errDiskHostWorker
		}
		canonical, _ := json.Marshal(old)
		if string(canonical) != string(raw) || old.Format != receipt.Format || old.JobID != receipt.JobID || old.ActorID != receipt.ActorID || old.RequestSHA != receipt.RequestSHA {
			return ack, errDiskHostWorker
		}
	} else if errors.Is(err, os.ErrNotExist) {
		raw, _ := json.Marshal(receipt)
		if err := j.WriteImmutable("cancel.json", raw); err != nil {
			return ack, err
		}
	} else {
		return ack, err
	}
	raw, err := j.Read("dispatch.json")
	if errors.Is(err, os.ErrNotExist) {
		return ack, guard()
	}
	if err != nil {
		return ack, err
	}
	d, err := diskjob.DecodeDispatch(raw, in)
	if err != nil {
		return ack, err
	}
	raw, err = j.Read("started.json")
	if errors.Is(err, os.ErrNotExist) {
		return ack, guard()
	} // durable Core intent stops pre-start worker
	if err != nil {
		return ack, err
	}
	started, err := diskjob.DecodeStarted(raw, d, in)
	if err != nil {
		return ack, err
	}
	if present, err := j.HasOriginalResult(); err != nil || present {
		return ack, err
	}
	if err := guard(); err != nil {
		return ack, err
	}
	ack.SignalRequested, err = diskjob.SignalOriginal(in, d, started)
	if err != nil {
		return ack, err
	}
	return ack, guard()
}

func (s *Service) diskHostCancelRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/disk-host-jobs/cancel", func(w http.ResponseWriter, r *http.Request) {
		var raw json.RawMessage
		if !readJSON(w, r, &raw) {
			return
		}
		in, err := diskjob.DecodeRequest(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": "原全盘取消请求无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		ack, err := s.diskHostCancel(ctx, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原全盘取消状态暂不能核对；没有认定结束或转向其他进程"})
			return
		}
		respond(w, 202, ack)
	})
}
