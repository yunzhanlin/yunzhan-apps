package core

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"local/panel/internal/appcatalog"
)

// Persist the COMPLETE original Root response and the Core terminal in ONE
// transaction. It is data-cache evidence, never an active Nginx policy claim.
// Existing terminals/results are not overwritten by a late observer.
func (s *Store) finishWAFCountryResult(ctx context.Context, j Job, raw []byte, actor string, selection WAFCountryDataSelection, steps []Step) error {
	out, err := DecodeWAFCountryDataOperation(raw, j.ID, actor, selection)
	if err != nil || out.State != "succeeded" && out.State != "failed" && out.State != "needs_attention" || len(steps) > 8 || ctx == nil || ctx.Err() != nil {
		return errors.New("国家数据完整原始结果不是可持久核对的终态")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	original, err := readWAFCountryOriginal(ctx, tx, j.ID)
	if err != nil || original.Actor != actor || original.Job.Payload != j.Payload || !SameWAFCountryDataSelection(original.Selection, selection) || j.Kind != "waf_country_data" || j.TargetID != "nginx-waf" {
		return errors.New("国家数据原始 Core 任务已改变；没有采用晚到结果")
	}
	if original.Job.State != "queued" && original.Job.State != "running" {
		return tx.Commit()
	}
	var existing int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM waf_country_results WHERE job_id=?`, j.ID).Scan(&existing) != nil || existing != 0 {
		return errors.New("国家数据原始结果已存在或不可读取，没有覆盖")
	}
	stamp := Now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO waf_country_results(job_id,request_sha256,result_sha256,body,state,created_at) VALUES(?,?,?,?,?,?)`, j.ID, out.RequestSHA, Hash(string(raw)), raw, out.State, stamp); err != nil {
		return err
	}
	encoded, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `UPDATE runtime_jobs SET state=?,error=?,steps=?,updated_at=? WHERE id=? AND state IN ('queued','running')`, out.State, out.Error, string(encoded), stamp, j.ID)
	if err != nil {
		return err
	}
	if changed, err := r.RowsAffected(); err != nil || changed != 1 {
		return errors.New("国家数据原终态未完整持久化")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('executor','waf.country.result',?,?,?)`, j.ID, out.State+":"+Hash(string(raw)), stamp); err != nil {
		return err
	}
	return tx.Commit()
}

func runWAFCountryDataJob(parent context.Context, s *Store, e *ExecutorClient, j Job, repo *appcatalog.Client) {
	ctx, cancel := context.WithTimeout(parent, 6*time.Minute)
	defer cancel()
	fail := func(detail string, uncertain bool) {
		if parent.Err() == nil {
			if err := s.finishRuntime(j, detail, nil, uncertain); err != nil {
				log.Printf("country original job terminal could not be persisted: %v", err)
			}
		}
	}
	original, err := readWAFCountryOriginal(ctx, s.DB, j.ID)
	if err != nil || original.Job.Payload != j.Payload || original.Job.State != "running" || j.Kind != "waf_country_data" || j.TargetID != "nginx-waf" || repo == nil || e == nil {
		fail("国家数据原任务完整身份不可核对", true)
		return
	}
	observeOnly, err := s.wafCountryDispatchBoundary(ctx, j, false)
	if err != nil {
		fail(err.Error(), true)
		return
	}
	var envelope appcatalog.GeoDataEnvelope
	if !observeOnly {
		var authority appcatalog.CountryDataAuthority
		envelope, authority, err = repo.FetchCountryDataEnvelope(ctx, original.Selection.DataManifestSHA, time.Now())
		if err != nil || authority.AppVersion() != original.Selection.AppVersion || authority.AppSHA256() != original.Selection.AppManifestSHA || authority.Data().Manifest().Release != original.Selection.Release || authority.Data().Manifest().Revision != original.Selection.Revision {
			fail("国家数据签名目录、应用或原始选择不同；没有提交下载", false)
			return
		}
		if _, err := authority.Data().Select(original.Selection.Countries); err != nil {
			fail("国家数据完整选择不在已验签容量边界内", false)
			return
		}
	}
	runWAFCountryOriginal(ctx, parent, s, e, j, original, envelope)
}

// Internal dispatch/observation mechanism. Production reaches this ONLY after
// original signed-source validation above (or an already committed dispatch
// intent). Transport tests may exercise it with explicit unsigned fixtures;
// the real Root endpoint independently rejects such fixtures in all cases.
func runWAFCountryOriginal(ctx, parent context.Context, s *Store, e *ExecutorClient, j Job, original wafCountryOriginal, envelope appcatalog.GeoDataEnvelope) {
	steps := []Step{{Time: Now(), Message: "仅准备已签名的国家网段数据；此任务不启用或修改 Nginx 防护策略"}}
	fail := func(detail string) {
		if parent.Err() == nil {
			if err := s.finishRuntime(j, detail, steps, true); err != nil {
				log.Printf("country original observation terminal could not be persisted: %v", err)
			}
		}
	}
	observeOnly, err := s.wafCountryDispatchBoundary(ctx, j, true)
	if err != nil {
		fail(err.Error())
		return
	}
	endpoint := "/v1/waf/country/jobs/" + j.ID
	query := WAFCountryObservationQuery(original.Actor, original.PayloadSHA)
	var raw json.RawMessage
	if !observeOnly {
		body := WAFCountryDataSubmission{original.Actor, original.Selection, envelope}
		submit, stop := context.WithTimeout(ctx, 15*time.Second)
		err = e.Call(submit, "POST", endpoint, body, &raw)
		stop()
		if err != nil {
			raw = nil
			steps = append(steps, Step{Time: Now(), Message: "唯一提交回执未确认；只读核对同一原任务，不重新 POST、下载或生成替代编号"})
		}
	}
	requestSHA := ""
	for {
		if len(raw) > 0 {
			out, err := DecodeWAFCountryDataOperation(raw, j.ID, original.Actor, original.Selection)
			if err != nil || requestSHA != "" && requestSHA != out.RequestSHA {
				fail("国家数据回执完整绑定改变；没有采用、启用或重发")
				return
			}
			requestSHA = out.RequestSHA
			switch out.State {
			case "succeeded", "failed", "needs_attention":
				if parent.Err() == nil {
					if err := s.finishWAFCountryResult(ctx, j, raw, original.Actor, original.Selection, steps); err != nil {
						fail("国家数据原结果未能完整持久化；只核对原任务：" + err.Error())
					}
				}
				return
			}
		}
		if ctx.Err() != nil {
			fail("国家数据原任务观察达到上限；没有认定完成或再次提交")
			return
		}
		observe, stop := context.WithTimeout(ctx, 8*time.Second)
		var next json.RawMessage
		err := e.Call(observe, "GET", endpoint+"?"+query.Encode(), nil, &next)
		stop()
		if err != nil {
			if !temporaryRuleFeedObservation(err) {
				fail("国家数据原任务无法完整核对：" + err.Error())
				return
			}
			raw = nil
		} else {
			raw = next
			if len(raw) == 0 {
				fail("国家数据原任务返回空回执，未重发")
				return
			}
			// Handle a terminal immediately; only pending/temporary observation
			// paths wait. There is never another POST in this loop.
			if out, err := DecodeWAFCountryDataOperation(raw, j.ID, original.Actor, original.Selection); err != nil || out.State != "queued" && out.State != "running" {
				continue
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}
