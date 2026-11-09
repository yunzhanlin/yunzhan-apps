//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func (s *Service) wafCountryDataState() (core.WAFCountryDataState, error) {
	out := core.WAFCountryDataState{MaxCountries: 32, MaxBytes: 64 << 20, MaxNetworks: 1 << 20, DownloadsDoNotActivatePolicy: true}
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Installed, out.AppVersion = true, manifest.Version
	if manifest.Version != core.WAFCountryDataVersion || !appcatalog.CountryDataSupported() {
		return out, nil
	}
	_, digest, err := s.readWAFCountryInstance()
	if err != nil {
		return out, err
	}
	if err := s.wafCountryInstanceGuard(digest); err != nil {
		return out, err
	}
	out.InstallationSHA, out.Supported = digest, true
	return out, nil
}

// One original durable dispatch. The callback is internal compiled code, not
// an API command/source/verification flag. A lost start reply never re-enters
// the callback, including after process or host restart.
func dispatchWAFCountryOriginal(ctx context.Context, store countryTaskStore, request countryTaskRequest, boot string, start func(context.Context, string) error) error {
	if ctx == nil || ctx.Err() != nil || start == nil {
		return errors.New("国家数据唯一派发上下文无效")
	}
	_, fresh, err := store.markDispatch(ctx, request, boot)
	if err != nil {
		return err
	}
	if !fresh {
		return nil // Read-only observation of old dispatch; never start again.
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return start(ctx, request.JobID)
}

func (s *Service) wafCountryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/waf/country", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			respond(w, 400, map[string]string{"error": "国家数据状态不接受路径或来源参数"})
			return
		}
		out, err := s.wafCountryDataState()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/waf/country/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		actor, payload, err := core.ParseWAFCountryObservationQuery(query)
		if queryErr != nil || err != nil || !core.ValidID(r.PathValue("id")) {
			respond(w, 400, map[string]string{"error": "原国家数据任务查询绑定无效"})
			return
		}
		out, err := s.wafCountryTaskStatus(r.Context(), r.PathValue("id"))
		if err != nil || out.ActorID != actor || out.PayloadSHA != payload {
			respond(w, 409, map[string]string{"error": "原国家数据任务或账户内容不能完整核对；未重发"})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/waf/country/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !core.ValidID(id) || r.URL.RawQuery != "" {
			respond(w, 400, map[string]string{"error": "国家数据原提交编号或参数无效"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, core.WAFCountrySubmissionMaxBytes))
		in, decodeErr := core.DecodeWAFCountryDataSubmission(raw)
		if err != nil || decodeErr != nil {
			respond(w, 400, map[string]string{"error": "国家数据原提交字段不完整、未规范或超出预算"})
			return
		}
		envelope, err := json.Marshal(in.Envelope)
		if err != nil {
			respond(w, 400, map[string]string{"error": "国家数据原交付编码失败"})
			return
		}
		request, _, fresh, err := s.prepareWAFCountryTask(r.Context(), id, in.Actor, in.Selection, envelope)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if fresh {
			boot, err := countryTaskBootID()
			if err == nil {
				err = dispatchWAFCountryOriginal(r.Context(), productionCountryTaskStore(), request, boot, func(ctx context.Context, originalID string) error {
					// Account preparation belongs to this SAME durable dispatch.
					// It is not tied to a body-engine build and is never replayed
					// when its reply or the following worker start is unknown.
					if err := s.ensureWAFCountryNetworkAccount(ctx, request); err != nil {
						return err
					}
					// Recheck actual installed unit immediately before the ONLY
					// systemd call. Its durable intent is already on disk.
					if err := verifyWAFCountryCoreOriginal(ctx, originalID, request.ActorID, request.PayloadSHA); err != nil {
						return err
					}
					if err := s.wafCountryInstanceGuard(request.Selection.InstallationSHA); err != nil {
						return err
					}
					if err := s.countryTaskUnitTrusted(ctx, originalID); err != nil {
						return err
					}
					_, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "start", "--no-block", "panel-waf-country@"+originalID+".service")
					return err
				})
			}
			if err != nil {
				respond(w, 409, map[string]string{"error": "国家数据原请求或唯一派发已封存，启动回执未确认；仅核对原ID，不再派发"})
				return
			}
			respond(w, 202, countryTaskOperation(request, "queued", ""))
			return
		}
		out, err := s.wafCountryTaskStatus(r.Context(), id)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原国家数据任务已存在但状态未确认；没有重新启动"})
			return
		}
		respond(w, 200, out)
	})
}
