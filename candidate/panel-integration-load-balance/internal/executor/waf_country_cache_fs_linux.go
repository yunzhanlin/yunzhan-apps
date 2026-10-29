//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

const countryCacheRoot = wafCountryDataRoot
const countryCacheMaxEntries = 64
const countryCacheMaxBytes int64 = 512 << 20

var countryDatasetName = regexp.MustCompile(`^[a-f0-9]{64}-[a-f0-9]{64}$`)
var countryStageName = regexp.MustCompile(`^\.country-stage-[a-f0-9]{32}$`)
var countryAssetName = regexp.MustCompile(`^[A-Z]{2}\.cidr$`)

// Internal-only seams: neither filesystem roots, keys, downloader nor fault
// callbacks can be deserialized from a panel request. This is PUBLIC DATA cache
// publication, not software installation or active Nginx policy selection.
type countryCacheStore struct {
	base  string
	trust *appcatalog.Client
	now   func() time.Time
	fault func(string) error
	guard func() error
	lease func(context.Context) (func() error, func(), error)
}

// Internal-only short commit lease; production binds the existing WAF SH
// lock and exact installation identity. Network transfer does not hold it.
func (s countryCacheStore) publicationLease(ctx context.Context) (func() error, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, errors.New("country cache commit context invalid")
	}
	if s.lease == nil {
		return func() error { return ctx.Err() }, func() {}, nil
	}
	check, release, err := s.lease(ctx)
	if err != nil {
		return nil, nil, err
	}
	if check == nil || release == nil {
		if release != nil {
			release()
		}
		return nil, nil, errors.New("country cache original commit lease incomplete")
	}
	return check, release, nil
}

type countryCachePlan struct {
	Format          int      `json:"format"`
	JobID           string   `json:"job_id"`
	DataManifestSHA string   `json:"data_manifest_sha256"`
	Countries       []string `json:"countries"`
}

type countryCacheReady struct {
	Format        int    `json:"format"`
	Dataset       string `json:"dataset"`
	OriginalJobID string `json:"original_job_id"`
	PlanSHA       string `json:"plan_sha256"`
	PreparedAt    string `json:"prepared_at"`
}

type countryCacheAborted struct {
	Format        int    `json:"format"`
	OriginalJobID string `json:"original_job_id"`
	PlanSHA       string `json:"plan_sha256"`
	AbortedAt     string `json:"aborted_at"`
}

func countryCacheJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
func countryCacheDecode(raw []byte, out any) error {
	if decodeProgramQueueJSON(raw, out) != nil {
		return errors.New("country cache record shape invalid")
	}
	canonical, err := countryCacheJSON(out)
	if err != nil || string(raw) != string(canonical) {
		return errors.New("country cache record is not original complete canonical bytes")
	}
	return nil
}
func countryCacheDatasetID(plan countryCachePlan) string {
	raw, _ := json.Marshal(plan.Countries)
	return plan.DataManifestSHA + "-" + core.Hash(string(raw))
}
func (s countryCacheStore) checkpoint(point string) error {
	if s.guard != nil {
		if err := s.guard(); err != nil {
			return err
		}
	}
	if s.fault != nil {
		return s.fault(point)
	}
	return nil
}
func (s countryCacheStore) open(create bool) (*statisticsGeoDirectory, error) {
	return (statisticsGeoStore{base: s.base, trust: s.trust, now: s.now}).open(create)
}

func countryCacheDirectory(base *statisticsGeoDirectory, name string) (*statisticsGeoDirectory, error) {
	if base == nil || !base.current() || !countryDatasetName.MatchString(name) && !countryStageName.MatchString(name) {
		return nil, errors.New("country cache directory identity invalid")
	}
	info, err := base.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !moduleRecordInfo(info, true, false) {
		return nil, errors.New("country cache leaf ownership/type/mode invalid; not repaired")
	}
	root, err := base.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	d := &statisticsGeoDirectory{root, filepath.Join(base.path, name), info}
	if !base.current() || !d.current() {
		root.Close()
		return nil, errors.New("country cache leaf changed during open")
	}
	return d, nil
}

func countryCacheFileLimit(name string) (int64, bool) {
	switch name {
	case "manifest.json":
		return geodata.MaxCountryManifestBytes, true
	case "manifest.sig":
		return 128, true
	case "request.json":
		return 4096, true
	case "ready.json", "abort.json":
		return 4096, true
	}
	if countryAssetName.MatchString(name) && name != "ZZ.cidr" {
		return geodata.MaxCountryCIDRBytes, true
	}
	return 0, false
}

func (s countryCacheStore) usage(ctx context.Context, base *statisticsGeoDirectory) (int64, int, error) {
	if ctx == nil || base == nil || !base.current() {
		return 0, 0, errors.New("country cache inventory authority missing")
	}
	f, err := base.Open(".")
	if err != nil {
		return 0, 0, err
	}
	entries, err := f.ReadDir(countryCacheMaxEntries + 2)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > countryCacheMaxEntries+1 {
		return 0, 0, errors.New("country cache entry capacity exceeded")
	}
	var total int64
	dirs := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		if entry.Name() == "store.lock" {
			info, err := base.Lstat(entry.Name())
			if err != nil || !moduleRecordInfo(info, false, false) || info.Size() != 0 {
				return 0, 0, errors.New("country cache lock identity invalid")
			}
			continue
		}
		dir, err := countryCacheDirectory(base, entry.Name())
		if err != nil {
			return 0, 0, err
		}
		dirs++
		d, err := dir.Open(".")
		if err != nil {
			dir.Close()
			return 0, 0, err
		}
		files, readErr := d.ReadDir(38)
		d.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || len(files) > 37 {
			dir.Close()
			return 0, 0, errors.New("country cache file set exceeds fixed capacity")
		}
		for _, file := range files {
			limit, ok := countryCacheFileLimit(file.Name())
			info, e := dir.Lstat(file.Name())
			if !ok || e != nil || !moduleRecordInfo(info, false, false) || info.Size() > limit || info.Size() < 0 {
				dir.Close()
				return 0, 0, errors.New("country cache unknown/unsafe file or size; not adopted")
			}
			total += info.Size()
			if total > countryCacheMaxBytes {
				dir.Close()
				return 0, 0, errors.New("country cache disk capacity exceeded")
			}
		}
		current := dir.current()
		dir.Close()
		if !current {
			return 0, 0, errors.New("country cache directory changed during inventory")
		}
	}
	if !base.current() || dirs > countryCacheMaxEntries {
		return 0, 0, errors.New("country cache root changed or directory capacity exceeded")
	}
	return total, dirs, nil
}

func countryCacheWriteNew(root *os.Root, name string, raw []byte) error {
	limit, ok := countryCacheFileLimit(name)
	if !ok || len(raw) == 0 || int64(len(raw)) > limit {
		return errors.New("country cache new metadata name or byte budget invalid")
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return hardeningJournalSync(root)
}

func countryCachePlanAuthority(plan countryCachePlan, a geodata.CountryAuthority) ([]geodata.CountryAsset, error) {
	if !countryCacheValidPlan(plan) || plan.DataManifestSHA != a.SHA256() {
		return nil, errors.New("country cache original task or signed selection invalid")
	}
	return a.Select(plan.Countries)
}

func countryCacheValidPlan(plan countryCachePlan) bool {
	if plan.Format != 1 || !core.ValidID(plan.JobID) || !wafLogDigestValid(plan.DataManifestSHA) || len(plan.Countries) < 1 || len(plan.Countries) > 32 {
		return false
	}
	previous := ""
	for _, code := range plan.Countries {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' || code == "ZZ" || code <= previous {
			return false
		}
		previous = code
	}
	return true
}

func countryCacheVerifyFile(ctx context.Context, root *os.Root, a geodata.CountryAuthority, asset geodata.CountryAsset) error {
	name := asset.Code + ".cidr"
	visible, err := root.Lstat(name)
	if err != nil || !moduleRecordInfo(visible, false, false) || visible.Size() != asset.Bytes {
		return errors.New("country cache signed asset identity missing or unsafe")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !geoStoreStableInfo(visible, opened) {
		return errors.New("country cache asset changed during open")
	}
	if _, err := geodata.VerifyCountryAsset(ctx, a, asset.Code, f); err != nil {
		return err
	}
	after, aerr := f.Stat()
	named, nerr := root.Lstat(name)
	if aerr != nil || nerr != nil || !geoStoreStableInfo(opened, after) || !geoStoreStableInfo(opened, named) || !moduleRecordInfo(after, false, false) || !moduleRecordInfo(named, false, false) {
		return errors.New("country cache asset changed during independent verification")
	}
	return nil
}

func countryCacheExpectedNames(plan countryCachePlan, ready bool) map[string]bool {
	seen := map[string]bool{"manifest.json": true, "manifest.sig": true, "request.json": true}
	if ready {
		seen["ready.json"] = true
	}
	for _, code := range plan.Countries {
		seen[code+".cidr"] = true
	}
	return seen
}

func countryCacheExactContents(root *os.Root, expected map[string]bool) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := f.ReadDir(37)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) != len(expected) || len(entries) > 36 {
		return errors.New("country cache file set incomplete or unbounded")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] || strings.ContainsAny(entry.Name(), "/\\") {
			return errors.New("country cache contains a foreign member; not repaired")
		}
	}
	return nil
}
