//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"local/panel/internal/core"
)

const countryTaskCompletionTimeout = 3 * time.Second

// Only the original, still-locked worker reaches this after its network work
// has returned. A cancelled download context must not prevent filesystem-only
// settlement. The independent short deadline does not authorize another fetch,
// dispatch, account creation or policy activation. Current authority is checked
// both before settlement and immediately before the append-only result.
// The callback is compiled by the fixed worker; it is not an API input.
func completeCountryTask(original context.Context, base, dir *statisticsGeoDirectory, lock *os.File, request countryTaskRequest, out core.WAFCountryDataOperation, cache *countryCacheStore, interrupted *countryCachePlan, current func(context.Context) error) (core.WAFCountryDataOperation, error) {
	if original == nil || base == nil || dir == nil || lock == nil || current == nil || !countryTaskRequestValid(request) {
		return out, errors.New("国家数据原工作收尾身份不完整，保留原结果待核对")
	}
	raw, err := json.Marshal(out)
	parsed, decodeErr := core.DecodeWAFCountryDataOperation(raw, request.JobID, request.ActorID, request.Selection)
	if err != nil || decodeErr != nil || parsed.RequestSHA != countryTaskRequestDigest(request) || parsed.State != "succeeded" && parsed.State != "failed" && parsed.State != "needs_attention" {
		return out, errors.New("国家数据原工作收尾结果内容不同，未改变原数据")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(original), countryTaskCompletionTimeout)
	defer cancel()
	check := func() error {
		if ctx.Err() != nil || !base.current() || !dir.current() {
			return errors.New("国家数据原工作收尾期限或目录身份改变")
		}
		if err := countryTaskRequireWorkerLock(dir, lock); err != nil {
			return err
		}
		return current(ctx)
	}
	if err := check(); err != nil {
		return out, err
	}
	if interrupted != nil {
		if cache == nil || interrupted.JobID != request.JobID || interrupted.DataManifestSHA != request.Selection.DataManifestSHA || !reflect.DeepEqual(interrupted.Countries, request.Selection.Countries) {
			return out, errors.New("国家数据原发布收尾内容或任务身份不同")
		}
		state, committed, err := cache.settlePublicationError(ctx, *interrupted)
		if err != nil {
			out.State = "needs_attention"
			out.Cache = nil
			out.Error = statisticsGeoBoundedError(fmt.Errorf("%s；原结果收尾尚未核对：%v", out.Error, err))
		} else {
			out.State, out.Cache = state, committed
			if state == "succeeded" {
				out.Error = ""
			}
		}
	}
	if out.Error == "" && out.State != "succeeded" {
		out.Error = "原始国家数据任务结果待核对，未重放"
	}
	if err := check(); err != nil {
		return out, err
	}
	if err := countryTaskPublishResult(ctx, dir, lock, request, out); err != nil {
		return out, errors.New("国家数据业务结果可能已发生但原回执未持久确认；只核对原ID，不重放")
	}
	return out, nil
}
