//go:build linux

package executor

import (
	"context"
	"errors"
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
	var interrupted *countryCachePlan
	if admissionErr != nil {
		operationErr = admissionErr
		out.Error = statisticsGeoBoundedError(admissionErr)
	} else {
		plan := countryCachePlan{1, id, request.Selection.DataManifestSHA, append([]string(nil), request.Selection.Countries...)}
		original := authority.Envelope()
		download, stopObserving := watchCountryDownloadCancellation(ctx, func(bounded context.Context) (bool, error) {
			return originalCountryDownloadCancellation(bounded, request)
		})
		entry, err := cache.publish(download, plan, original.DataManifest, original.DataSignature, service.countryIsolatedDownload(request.Selection, authority))
		requestedCancellation := errors.Is(context.Cause(download), errCountryOriginalDownloadCancelled)
		stopObserving()
		if err != nil {
			operationErr = err
			out.State = "needs_attention"
			out.Error = statisticsGeoBoundedError(err)
			if requestedCancellation {
				operationErr = errCountryOriginalDownloadCancelled
				out.Error = core.WAFCountryDownloadCancelledMessage
			}
			interrupted = &plan
		} else {
			out.State = "succeeded"
			out.Cache = &entry
		}
	}
	current := func(final context.Context) error {
		if err := countryCheckOwnProcess(true); err != nil {
			return err
		}
		if err := upgradeguard.CheckStartup(); err != nil {
			return err
		}
		marker, err := countryTaskReadStarted(dir.Root, request)
		if err != nil || marker != started {
			return errors.New("国家数据原工作启动身份改变，未补建收尾")
		}
		if err := countryTaskLiveProcess(final, started); err != nil {
			return err
		}
		// Rebuild only the original filesystem-settlement authority against
		// this independent bounded context. The original signature, current
		// original Core permission OR its complete historical stop request,
		// and unchanged installation are checked at every cache checkpoint.
		// No network/dispatch/republication authority is granted here.
		refreshed, err := service.countryTaskSettlementAuthority(final, request, envelope)
		if err != nil {
			return err
		}
		cache = refreshed
		return nil
	}
	out, err = completeCountryTask(ctx, base, dir, lock, request, out, &cache, interrupted, current)
	if err != nil {
		return err
	}
	if out.State == "succeeded" {
		return nil
	}
	return operationErr
}
