//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

func verifyWAFCountryCoreOriginal(ctx context.Context, id, actor, payloadSHA string) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("国家数据原任务授权上下文失效")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return err
	}
	defer reader.db.Close()
	if !reader.current() {
		return errors.New("国家数据原Core数据库身份改变")
	}
	if err := (&core.Store{DB: reader.db}).ValidateWAFCountryDataNative(bounded, id, actor, payloadSHA); err != nil {
		return err
	}
	if !reader.current() {
		return errors.New("国家数据核对期间Core数据库身份改变")
	}
	return nil
}

// Only production's fixed environment is constructed here. No caller key,
// URL, alternate root, executable, verification flag or downloader is accepted.
// The whole signed app/data envelope is mandatory even though the cache itself
// is reusable public data and never activates a website rule.
func (s *Service) authorizeWAFCountryData(ctx context.Context, id, actor string, in core.WAFCountryDataSelection, raw []byte) (countryCacheStore, appcatalog.CountryDataAuthority, error) {
	var none countryCacheStore
	var empty appcatalog.CountryDataAuthority
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" || !core.ValidID(id) || !core.ValidID(actor) || core.ValidateWAFCountryDataSelection(in) != nil || len(raw) < 1 || len(raw) > appcatalog.MaxGeoDataEnvelopeBytes {
		return none, empty, errors.New("国家数据固定Root环境或原请求无效")
	}
	in.Countries = append([]string(nil), in.Countries...)
	if err := upgradeguard.CheckStartup(); err != nil {
		return none, empty, err
	}
	envelope, err := appcatalog.DecodeGeoDataEnvelope(raw)
	if err != nil {
		return none, empty, err
	}
	trust := appcatalog.Default()
	authority, err := trust.VerifyCountryDataEnvelope(envelope, in.AppVersion, in.AppManifestSHA, time.Now(), nil)
	if err != nil {
		return none, empty, err
	}
	manifest := authority.Data().Manifest()
	if authority.Data().SHA256() != in.DataManifestSHA || manifest.Release != in.Release || manifest.Revision != in.Revision {
		return none, empty, errors.New("国家数据完整签名与明确选择不同")
	}
	if _, err := authority.Data().Select(in.Countries); err != nil {
		return none, empty, err
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return none, empty, err
	}
	payloadSHA := core.Hash(string(payload))
	guard := func() error {
		if err := upgradeguard.CheckStartup(); err != nil {
			return err
		}
		if err := verifyWAFCountryCoreOriginal(ctx, id, actor, payloadSHA); err != nil {
			return err
		}
		return s.wafCountryInstanceGuard(in.InstallationSHA)
	}
	if err := guard(); err != nil {
		return none, empty, err
	}
	lease := s.wafCountryPublicationLease(in.InstallationSHA)
	store := countryCacheStore{base: countryCacheRoot, trust: trust, now: time.Now, guard: guard, lease: func(ctx context.Context) (func() error, func(), error) {
		check, release, err := lease(ctx)
		if err != nil {
			return nil, nil, err
		}
		return func() error {
			if err := guard(); err != nil {
				return err
			}
			return check()
		}, release, nil
	}}
	return store, authority, nil
}
