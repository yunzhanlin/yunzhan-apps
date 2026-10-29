//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestWAFCountryInstanceSameSecondInstallAndUpgradeAlwaysHaveDistinctRandomIdentity(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	seen := map[string]bool{}
	for _, version := range []string{"", "2.0.1", "2.1.0", "2.1.1", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.5.1", "2.5.2", ""} {
		raw, present, err := planWAFCountryInstanceBytes(version, nil, false, false, now)
		if err != nil || !present {
			t.Fatal(version, present, err)
		}
		record, err := decodeWAFCountryInstance(raw)
		if err != nil || seen[record.ID] || record.CreatedAt != now.Format(time.RFC3339) {
			t.Fatal("same-second reinstall reused identity", record, err)
		}
		seen[record.ID] = true
	}
}

func TestWAFCountryInstanceConfigurationPreservesOriginalAndUninstallDoesNotRecreate(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	original, _, err := planWAFCountryInstanceBytes("", nil, false, false, now)
	if err != nil {
		t.Fatal(err)
	}
	preserved, present, err := planWAFCountryInstanceBytes(core.WAFCountryDataVersion, original, true, false, now.Add(time.Hour))
	if err != nil || !present || !bytes.Equal(original, preserved) {
		t.Fatal("configuration changed installation identity", err)
	}
	preserved[0] = '!'
	if _, err := decodeWAFCountryInstance(original); err != nil {
		t.Fatal("caller changed original plan bytes", err)
	}
	removed, present, err := planWAFCountryInstanceBytes(core.WAFCountryDataVersion, original, true, true, now.Add(time.Hour))
	if err != nil || present || len(removed) != 0 {
		t.Fatal("uninstall generated another instance", removed, present, err)
	}
	for _, version := range []string{"", "2.5.1", "2.5.2"} {
		got, present, err := planWAFCountryInstanceBytes(version, nil, false, true, now)
		if err != nil || present || len(got) != 0 {
			t.Fatal("old-version uninstall created identity", got, present, err)
		}
	}
}

func TestWAFCountryInstanceMissingForeignAndMalformedRecordsNeverRepaired(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	raw, _, err := planWAFCountryInstanceBytes("", nil, false, false, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("{}"), append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"format": 1`), []byte(`"format": 1, "format": 1`), 1), bytes.Replace(raw, []byte(`"instance_id"`), []byte(`"Instance_id"`), 1), bytes.Replace(raw, []byte(`"nginx-waf"`), []byte(`"apache-waf"`), 1)} {
		if got, present, err := planWAFCountryInstanceBytes(core.WAFCountryDataVersion, bad, true, false, now); err == nil || present || len(got) != 0 {
			t.Fatal("malformed instance repaired", present, err)
		}
	}
	for _, item := range []struct {
		version string
		raw     []byte
		exists  bool
	}{{core.WAFCountryDataVersion, nil, false}, {"", raw, true}, {"2.5.1", raw, true}, {"2.5.2", raw, true}, {"2.5.3", nil, false}, {"2.7.0", nil, false}, {"2.6.0-build", nil, false}} {
		if got, present, err := planWAFCountryInstanceBytes(item.version, item.raw, item.exists, false, now); err == nil || present || len(got) != 0 {
			t.Fatal("missing or foreign identity adopted", item.version, present, err)
		}
	}
}

func TestCountryCacheShortPublicationLeaseStartsAfterTransferAndIsAlwaysReleased(t *testing.T) {
	for _, kind := range []string{"success", "acquire-fails", "first-check-fails", "second-check-fails", "missing-check"} {
		t.Run(kind, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			checks, leases, released := 0, 0, 0
			f.store.lease = func(ctx context.Context) (func() error, func(), error) {
				leases++
				if f.downloads != 2 {
					t.Fatal("network held the WAF commit lease")
				}
				if kind == "acquire-fails" {
					return nil, nil, errors.New("another configuration writer")
				}
				release := func() { released++ }
				if kind == "missing-check" {
					return nil, release, nil
				}
				return func() error {
					checks++
					if kind == "first-check-fails" && checks == 1 || kind == "second-check-fails" && checks == 2 {
						return errors.New("original instance/lock revoked")
					}
					return ctx.Err()
				}, release, nil
			}
			got, err := f.publish()
			if kind == "success" {
				if err != nil || !got.Published || got.ActivatedNginxPolicy || checks != 2 {
					t.Fatal(got, err, checks)
				}
			} else {
				if err == nil || got.Published {
					t.Fatal("unqualified commit lease published", got, err)
				}
				requireCountryCacheAbsent(t, f)
			}
			want := 1
			if kind == "acquire-fails" {
				want = 0
			}
			if leases != 1 || released != want {
				t.Fatal("commit lease missing or leaked", leases, released)
			}
		})
	}
}

func TestCountryCacheExplicitFinalizeNeedsANewQualifiedShortCommitLeaseNotAnotherDownload(t *testing.T) {
	f := newCountryCacheFixture(t)
	f.store.fault = func(point string) error {
		if point == "before-ready" {
			return errors.New("interrupted")
		}
		return nil
	}
	if _, err := f.publish(); err == nil {
		t.Fatal("no interruption")
	}
	f.store.fault = nil
	released := 0
	f.store.lease = func(context.Context) (func() error, func(), error) {
		return func() error { return errors.New("current instance changed") }, func() { released++ }, nil
	}
	if got, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest()); err == nil || got.Published || released != 1 || f.downloads != 2 {
		t.Fatal("finalize ignored original authority", got, err)
	}
	requireCountryCacheAbsent(t, f)
	f.store.lease = func(context.Context) (func() error, func(), error) {
		return func() error { return nil }, func() { released++ }, nil
	}
	got, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest())
	if err != nil || !got.Published || got.ActivatedNginxPolicy || released != 2 || f.downloads != 2 {
		t.Fatal(got, err, released)
	}
}

func TestWAFCountryInstanceStandaloneMetadataCannotMakeOldWAFAnInstalledCountryCapability(t *testing.T) {
	f := newCountryCacheFixture(t)
	root := filepath.Dir(f.store.base)
	security := filepath.Join(root, "security")
	if err := os.Mkdir(security, 0700); err != nil {
		t.Fatal(err)
	}
	s := New(Config{SystemRoot: root, SecurityDir: security})
	if err := s.writeSoftwareManifest(softwareManifest{ID: "nginx-waf", Version: "2.5.1", Settings: core.WAFSettings(core.DefaultWAFConfig()), InstalledAt: core.Now()}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := planWAFCountryInstanceBytes("", nil, false, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.wafCountryInstancePath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, digest, err := s.readWAFCountryInstance()
	if err != nil || digest != core.Hash(string(raw)) {
		t.Fatal("private metadata not independently readable", digest, err)
	}
	if s.wafCountryInstanceGuard(digest) == nil {
		t.Fatal("metadata alone upgraded old WAF")
	}
	if s.wafCountryInstanceGuard(strings.Repeat("a", 64)) == nil {
		t.Fatal("foreign instance adopted")
	}
}
