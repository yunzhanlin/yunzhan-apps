//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

func originalCountryDownloadCancellation(ctx context.Context, request countryTaskRequest) (bool, error) {
	if ctx == nil || ctx.Err() != nil || !countryTaskRequestValid(request) {
		return false, errors.New("原国家下载取消核对上下文或请求失效")
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return false, err
	}
	defer reader.db.Close()
	if !reader.current() {
		return false, errors.New("原国家下载取消核对期间数据库身份改变")
	}
	requested, err := (&core.Store{DB: reader.db}).WAFCountryDownloadCancellationNative(ctx, request.JobID, request.ActorID, request.PayloadSHA, countryTaskRequestDigest(request))
	if err != nil || !reader.current() {
		return false, errors.New("原国家下载取消请求不能完整核对")
	}
	return requested, nil
}

// Settlement-only historical authority. This constructor is called only
// by the still-locked original worker AFTER its network operation returned.
// The returned store is passed only to completeCountryTask's settlement path,
// never its network publication path. Current download permission OR a complete
// historically authorized original stop proof is required on EVERY checkpoint;
// an unchanged WAF installation is always required. This avoids a role change
// halfway through aborting the original partial stage. The existing independent
// three-second completion deadline and the original worker lock are unchanged.
func (s *Service) countryTaskSettlementAuthority(ctx context.Context, request countryTaskRequest, envelope []byte) (countryCacheStore, error) {
	var empty countryCacheStore
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" || !countryTaskRequestValid(request) {
		return empty, errors.New("原国家下载取消收尾固定环境无效")
	}
	if core.Hash(string(envelope)) != request.EnvelopeSHA {
		return empty, errors.New("原国家下载的签名信封摘要改变")
	}
	if err := verifyCountryFailedEnvelope(request, envelope); err != nil {
		return empty, err
	}
	guard := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := upgradeguard.CheckStartup(); err != nil {
			return err
		}
		if err := verifyWAFCountryCoreOriginal(ctx, request.JobID, request.ActorID, request.PayloadSHA); err != nil {
			requested, stopErr := originalCountryDownloadCancellation(ctx, request)
			if stopErr != nil || !requested {
				return errors.New("原国家下载当前收尾权限或原取消请求不能完整核对")
			}
		}
		return s.wafCountryInstanceGuard(request.Selection.InstallationSHA)
	}
	if err := guard(); err != nil {
		return empty, err
	}
	lease := s.wafCountryPublicationLease(request.Selection.InstallationSHA)
	// Keep the real wall clock for abort timestamps and any committed-cache
	// verification. Historical envelope checks never refresh expired data.
	return countryCacheStore{base: countryCacheRoot, trust: appcatalog.Default(), now: time.Now, guard: guard, lease: func(bounded context.Context) (func() error, func(), error) {
		check, release, err := lease(bounded)
		if err != nil {
			return nil, nil, err
		}
		return func() error {
			if err := guard(); err != nil {
				return err
			}
			return check()
		}, release, nil
	}}, nil
}
