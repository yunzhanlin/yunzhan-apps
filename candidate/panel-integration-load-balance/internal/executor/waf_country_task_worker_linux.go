//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

// Fixed Root entry: ONE original sealed data task, no path/key/source/command
// flags. A durable actual-worker identity precedes reauthorization and network
// work. Any previous start/result blocks execution, including after power loss.
// This function never installs software or changes a website/Nginx selector.
func RunWAFCountryDataJob(id string) error {
	if os.Geteuid() != 0 || !core.ValidID(id) {
		return errors.New("国家数据固定工作入口身份无效")
	}
	if err := countryCheckOwnProcess(true); err != nil {
		return err
	}
	if err := upgradeguard.CheckStartup(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 270*time.Second)
	defer cancel()
	store := productionCountryTaskStore()
	base, err := store.open(false)
	if err != nil {
		return err
	}
	defer base.Close()
	request, envelope, dir, err := store.read(base, id)
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := countryTaskWorkerLock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	boot, err := countryTaskBootID()
	if err != nil {
		return err
	}
	ticks, err := diskHostStartTicks()
	if err != nil {
		return err
	}
	exe, err := diskHostExecutableSHA()
	if err != nil {
		return err
	}
	started := countryTaskStarted{1, id, countryTaskRequestDigest(request), boot, os.Getpid(), ticks, exe}
	if err := countryTaskPublishStarted(ctx, dir, lock, request, started); err != nil {
		return err
	}
	out := countryTaskOperation(request, "failed", "")
	service := New(Config{})
	cache, authority, admissionErr := service.authorizeWAFCountryData(ctx, id, request.ActorID, request.Selection, envelope)
	var operationErr error
	if admissionErr != nil {
		operationErr = admissionErr
		out.Error = statisticsGeoBoundedError(admissionErr)
	} else {
		plan := countryCachePlan{1, id, request.Selection.DataManifestSHA, append([]string(nil), request.Selection.Countries...)}
		original := authority.Envelope()
		entry, err := cache.publish(ctx, plan, original.DataManifest, original.DataSignature, service.countryIsolatedDownload(request.Selection, authority))
		if err != nil {
			operationErr = err
			out.State = "needs_attention"
			out.Error = statisticsGeoBoundedError(err)
			// Observe this same still-owned operation. Only an independently
			// re-read original commit is success; a proved uncommitted outcome
			// closes failed while retaining partial bytes and an abort seal.
			state, committed, settleErr := cache.settlePublicationError(ctx, plan)
			if settleErr == nil {
				out.State, out.Cache = state, committed
				if state == "succeeded" {
					operationErr, out.Error = nil, ""
				}
			} else {
				out.Error = statisticsGeoBoundedError(fmt.Errorf("%v；原结果收尾尚未核对：%v", err, settleErr))
			}
		} else {
			out.State = "succeeded"
			out.Cache = &entry
		}
	}
	if out.Error == "" && out.State != "succeeded" {
		out.Error = "原始国家数据任务结果待核对，未重放"
	}
	if !base.current() || !dir.current() {
		return errors.New("国家数据原工作目录改变，原任务保留待核对")
	}
	if err := countryTaskPublishResult(ctx, dir, lock, request, out); err != nil {
		return errors.New("国家数据业务结果可能已发生但原回执未持久确认；只核对原ID，不重放")
	}
	return operationErr
}
