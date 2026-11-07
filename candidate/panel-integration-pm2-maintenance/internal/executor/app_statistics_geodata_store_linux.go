//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

const statisticsGeoDataRoot = "/var/lib/panel-executor/statistics-geodata"

var statisticsGeoName = regexp.MustCompile(`^dbip-city-lite-v1-20[2-9][0-9]-(0[1-9]|1[0-2])-[0-9a-f]{64}$`)

// Internal configuration only. Neither base, key, HTTP client nor fault hook
// can be deserialized from a panel request. Production construction is root-only.
type statisticsGeoStore struct {
	base   string
	trust  *appcatalog.Client
	now    func() time.Time
	fault  func(string) error
	guard  func() error
	verify func(context.Context, geodata.Manifest, io.Reader) error
}
type statisticsGeoSelector struct {
	Format    int    `json:"format"`
	Dataset   string `json:"dataset"`
	Previous  string `json:"previous"`
	UpdatedAt string `json:"updated_at"`
}

func (s *Service) statisticsGeoDataStore() (statisticsGeoStore, error) {
	if os.Geteuid() != 0 || s.Config.SystemRoot != "/" {
		return statisticsGeoStore{}, errors.New("地理数据只能由固定 root 安装环境管理")
	}
	return statisticsGeoStore{base: statisticsGeoDataRoot, trust: appcatalog.Default(), now: time.Now}, nil
}
func geoStoreName(a appcatalog.GeoDataAuthority) string {
	return geodata.Channel + "-" + a.Data().Manifest().Release + "-" + a.Data().SHA256()
}
func (store statisticsGeoStore) checkpoint(point string) error {
	if store.fault != nil {
		return store.fault(point)
	}
	return nil
}

// Unlike a temporary-file convenience helper, the data store never tolerates
// writable/sticky parents, symlinks or a foreign owner. Tests use trusted /var.
func statisticsGeoParents(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("地理库目录须为固定绝对路径")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("地理库父目录类型或权限异常，未接管")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return errors.New("地理库父目录不属于 root，未接管")
		}
		if current == "/" {
			return nil
		}
	}
}

type statisticsGeoDirectory struct {
	*os.Root
	path     string
	identity os.FileInfo
}

func (d *statisticsGeoDirectory) current() bool {
	visible, err := os.Lstat(d.path)
	opened, openedErr := d.Stat(".")
	return err == nil && openedErr == nil && os.SameFile(d.identity, visible) && os.SameFile(d.identity, opened) && moduleRecordInfo(visible, true, false) && moduleRecordInfo(opened, true, false) && statisticsGeoParents(d.path) == nil
}
func (store statisticsGeoStore) open(create bool) (*statisticsGeoDirectory, error) {
	if os.Geteuid() != 0 || store.trust == nil || store.now == nil || !filepath.IsAbs(store.base) || filepath.Clean(store.base) != store.base {
		return nil, errors.New("地理库受信环境未初始化")
	}
	if err := statisticsGeoParents(filepath.Dir(store.base)); err != nil {
		return nil, err
	}
	if create {
		if err := os.Mkdir(store.base, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	info, err := os.Lstat(store.base)
	if err != nil {
		return nil, err
	}
	if !moduleRecordInfo(info, true, false) {
		return nil, errors.New("地理库已有目录身份或权限异常，未修复")
	}
	root, err := os.OpenRoot(store.base)
	if err != nil {
		return nil, err
	}
	d := &statisticsGeoDirectory{root, store.base, info}
	if !d.current() {
		root.Close()
		return nil, errors.New("地理库目录打开期间身份改变")
	}
	return d, nil
}
func geoStoreStableInfo(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Size() != b.Size() || a.ModTime() != b.ModTime() || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Ctim == y.Ctim
}
func geoStoreRead(root *os.Root, name string, limit int64) ([]byte, error) {
	raw, _, err := geoStoreReadIdentity(root, name, limit)
	return raw, err
}
func geoStoreReadIdentity(root *os.Root, name string, limit int64) ([]byte, os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !moduleRecordInfo(info, false, false) || info.Size() < 1 || info.Size() > limit {
		return nil, nil, errors.New("地理库记录类型、身份或容量异常")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !geoStoreStableInfo(info, opened) {
		return nil, nil, errors.New("地理库记录打开期间变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, aerr := f.Stat()
	visible, verr := root.Lstat(name)
	if err != nil || aerr != nil || verr != nil || int64(len(raw)) != info.Size() || !geoStoreStableInfo(info, after) || !geoStoreStableInfo(info, visible) || !moduleRecordInfo(after, false, false) || !moduleRecordInfo(visible, false, false) {
		return nil, nil, errors.New("地理库记录读取期间变化")
	}
	return raw, info, nil
}
func geoStoreLock(root *os.Root) (*os.File, error) {
	f, err := root.OpenFile("store.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = root.OpenFile("store.lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	visible, verr := root.Lstat("store.lock")
	if err != nil || verr != nil || !moduleRecordInfo(opened, false, false) || !moduleRecordInfo(visible, false, false) || !geoStoreStableInfo(opened, visible) || opened.Size() != 0 {
		f.Close()
		return nil, errors.New("地理库锁身份异常")
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("地理库操作正在进行；保留当前库")
	}
	return f, nil
}
func decodeStatisticsGeoSelector(raw []byte, out *statisticsGeoSelector) error {
	if len(raw) < 1 || len(raw) > 1024 || !utf8.Valid(raw) {
		return errors.New("地理库选择记录容量或编码无效")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("地理库选择记录须为对象")
	}
	allowed := map[string]bool{"format": true, "dataset": true, "previous": true, "updated_at": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return errors.New("地理库选择字段重复、未知或名称不规范")
		}
		seen[name] = true
		v, err := d.Token()
		if err != nil {
			return err
		}
		if name == "format" {
			if _, ok := v.(json.Number); !ok {
				return errors.New("地理库选择格式无效")
			}
		} else if _, ok := v.(string); !ok {
			return errors.New("地理库选择身份须为字符串")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != 4 {
		return errors.New("地理库选择字段不完整")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("地理库选择含多余值")
	}
	return json.Unmarshal(raw, out)
}
func (store statisticsGeoStore) selector(root *os.Root) (statisticsGeoSelector, []byte, os.FileInfo, error) {
	var selected statisticsGeoSelector
	raw, identity, err := geoStoreReadIdentity(root, "selected.json", 1024)
	if errors.Is(err, os.ErrNotExist) {
		return selected, nil, nil, nil
	}
	if err != nil {
		return selected, nil, nil, err
	}
	stamp, parseErr := time.Time{}, error(nil)
	if decodeStatisticsGeoSelector(raw, &selected) == nil {
		stamp, parseErr = time.Parse(time.RFC3339, selected.UpdatedAt)
	} else {
		parseErr = errors.New("invalid selector")
	}
	if selected.Format != 1 || !statisticsGeoName.MatchString(selected.Dataset) || selected.Previous != "" && !statisticsGeoName.MatchString(selected.Previous) || selected.Previous == selected.Dataset || parseErr != nil || stamp.UTC().Format(time.RFC3339) != selected.UpdatedAt || stamp.After(store.now().Add(time.Hour)) {
		return selected, nil, nil, errors.New("地理库选择记录损坏；未猜测或自动切换")
	}
	return selected, raw, identity, nil
}
func (store statisticsGeoStore) inventory(root *statisticsGeoDirectory) ([]string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := dir.ReadDir(33)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 32 || !root.current() {
		return nil, errors.New("地理库条目数量或目录身份异常")
	}
	names := []string{}
	for _, entry := range entries {
		name := entry.Name()
		info, err := root.Lstat(name)
		if err != nil {
			return nil, err
		}
		if name == ".archive" {
			if !moduleRecordInfo(info, true, false) {
				return nil, errors.New("地域数据私有归档目录身份异常")
			}
			continue
		}
		if name == "store.lock" || name == "selected.json" || strings.HasPrefix(name, ".selector-") && core.ValidID(strings.TrimPrefix(name, ".selector-")) {
			if !moduleRecordInfo(info, false, false) || info.Size() > 1024 {
				return nil, errors.New("地理库控制记录身份异常")
			}
			continue
		}
		stage := strings.HasPrefix(name, ".stage-") && core.ValidID(strings.TrimPrefix(name, ".stage-"))
		if !moduleRecordInfo(info, true, false) || !stage && !statisticsGeoName.MatchString(name) {
			return nil, errors.New("地理库存放目录存在未知或不受信条目，未接管")
		}
		if !stage {
			names = append(names, name)
		}
	}
	return names, nil
}
func (store statisticsGeoStore) authority(root *os.Root, name string) (appcatalog.GeoDataAuthority, error) {
	var empty appcatalog.GeoDataAuthority
	if !statisticsGeoName.MatchString(name) {
		return empty, errors.New("地理库数据身份无效")
	}
	info, err := root.Lstat(name)
	if err != nil || !moduleRecordInfo(info, true, false) {
		return empty, errors.New("地理库副本目录身份异常")
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return empty, err
	}
	defer child.Close()
	opened, err := child.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, true, false) {
		return empty, errors.New("地理库副本打开期间变化")
	}
	f, err := child.Open(".")
	if err != nil {
		return empty, err
	}
	entries, err := f.ReadDir(4)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) != 3 {
		return empty, errors.New("地理库副本成员集合不同")
	}
	allowed := map[string]bool{"envelope.json": true, "database.mmdb.gz": true, "NOTICE.txt": true}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return empty, errors.New("地理库副本有未知成员")
		}
	}
	raw, err := geoStoreRead(child, "envelope.json", appcatalog.MaxGeoDataEnvelopeBytes)
	if err != nil {
		return empty, err
	}
	in, err := appcatalog.DecodeGeoDataEnvelope(raw)
	if err != nil {
		return empty, err
	}
	a, err := store.trust.VerifyGeoDataEnvelope(in, "2.6.0", core.Hash(string(in.AppManifest)), store.now(), nil)
	if err != nil || geoStoreName(a) != name {
		return empty, errors.New("地理库原始双签名与目录身份不符")
	}
	data, err := child.Lstat("database.mmdb.gz")
	if err != nil || !moduleRecordInfo(data, false, false) || data.Size() != a.Data().Manifest().CompressedBytes {
		return empty, errors.New("地理库压缩数据路径、身份或大小异常")
	}
	notice, err := geoStoreRead(child, "NOTICE.txt", 4096)
	if err != nil || !bytes.Equal(notice, statisticsGeoNotice(a)) {
		return empty, errors.New("地理库归属或许可记录不同")
	}
	visible, err := root.Lstat(name)
	if err != nil || !os.SameFile(info, visible) || !moduleRecordInfo(visible, true, false) {
		return empty, errors.New("地理库副本目录读取期间变化")
	}
	return a, nil
}
func statisticsGeoNotice(a appcatalog.GeoDataAuthority) []byte {
	m := a.Data().Manifest()
	return []byte("DB-IP City Lite " + m.Release + "\nIP Geolocation by DB-IP\n" + geodata.AttributionURL + "\nLicense: CC BY 4.0\n" + geodata.LicenseURL + "\nSource: " + m.Source + "\nOriginal gzip and MMDB bytes are unchanged. YunZhan adds a signed identity manifest and offline aggregation. No endorsement is implied. Network locations are approximate, not physical/device locations. Lite coverage and accuracy are limited. Keep this notice and license with redistributed data; result pages must link to DB-IP.\n")
}
func (store statisticsGeoStore) load(ctx context.Context, root *os.Root, name string) (appcatalog.GeoDataAuthority, *geodata.Snapshot, os.FileInfo, error) {
	a, err := store.authority(root, name)
	if err != nil {
		return a, nil, nil, err
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return a, nil, nil, err
	}
	defer child.Close()
	info, err := child.Lstat("database.mmdb.gz")
	if err != nil {
		return a, nil, nil, err
	}
	f, err := child.OpenFile("database.mmdb.gz", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return a, nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !geoStoreStableInfo(info, opened) || !moduleRecordInfo(opened, false, false) {
		return a, nil, nil, errors.New("地理库数据打开期间变化")
	}
	var snapshot *geodata.Snapshot
	if store.verify == nil {
		snapshot, err = geodata.Open(ctx, a.Data(), f)
	} else {
		snapshot, err = geodata.OpenWithStructureVerifier(ctx, a.Data(), f, store.verify)
	}
	if err != nil {
		return a, nil, nil, err
	}
	after, aerr := f.Stat()
	visible, verr := child.Lstat("database.mmdb.gz")
	if aerr != nil || verr != nil || !geoStoreStableInfo(info, after) || !geoStoreStableInfo(info, visible) {
		snapshot.Close()
		return a, nil, nil, errors.New("地理库校验期间文件身份或内容变化")
	}
	return a, snapshot, info, nil
}

type geoStoreContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r geoStoreContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func (store statisticsGeoStore) publicationCurrent(ctx context.Context, root *statisticsGeoDirectory, name string, verified os.FileInfo) bool {
	if store.guard != nil && store.guard() != nil {
		return false
	}
	if ctx == nil || ctx.Err() != nil || verified == nil || !root.current() {
		return false
	}
	a, err := store.authority(root.Root, name)
	if err != nil {
		return false
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return false
	}
	defer child.Close()
	current, err := child.Lstat("database.mmdb.gz")
	if err != nil || !moduleRecordInfo(current, false, false) || !geoStoreStableInfo(verified, current) {
		return false
	}
	f, err := child.OpenFile("database.mmdb.gz", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !moduleRecordInfo(opened, false, false) || !geoStoreStableInfo(verified, opened) {
		return false
	}
	m := a.Data().Manifest()
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(geoStoreContextReader{ctx, f}, m.CompressedBytes+1))
	after, afterErr := f.Stat()
	visible, visibleErr := child.Lstat("database.mmdb.gz")
	return err == nil && n == m.CompressedBytes && hex.EncodeToString(digest.Sum(nil)) == m.CompressedSHA256 && afterErr == nil && visibleErr == nil && geoStoreStableInfo(verified, after) && geoStoreStableInfo(verified, visible) && root.current() && ctx.Err() == nil
}
func geoSelectorSameIdentity(before, current os.FileInfo) bool {
	if before == nil || current == nil {
		return before == nil && current == nil
	}
	return geoStoreStableInfo(before, current)
}
func (store statisticsGeoStore) publishSelection(ctx context.Context, root *statisticsGeoDirectory, name string, before []byte, beforeIdentity, verified os.FileInfo) error {
	prior, raw, identity, err := store.selector(root.Root)
	if err != nil || !bytes.Equal(raw, before) || !geoSelectorSameIdentity(beforeIdentity, identity) || !store.publicationCurrent(ctx, root, name, verified) {
		return errors.New("地理库选择发生外部变化，未覆盖")
	}
	if prior.Dataset == name {
		return nil
	}
	selected := statisticsGeoSelector{1, name, prior.Dataset, store.now().UTC().Format(time.RFC3339)}
	next, err := json.Marshal(selected)
	if err != nil {
		return err
	}
	stage := ".selector-" + core.ID()
	if err = ruleFeedStoreWrite(root.Root, stage, next, 0600); err != nil {
		return err
	}
	if err = store.checkpoint("selector-written"); err != nil {
		return err
	}
	_, current, identity, err := store.selector(root.Root)
	if err != nil || !bytes.Equal(current, before) || !geoSelectorSameIdentity(beforeIdentity, identity) || !store.publicationCurrent(ctx, root, name, verified) {
		return errors.New("地理库选择提交前发生外部变化，未覆盖")
	}
	if err = root.Rename(stage, "selected.json"); err != nil {
		return err
	}
	if err = ruleFeedStoreSync(root.Root); err != nil {
		return fmt.Errorf("地理库选择可能已提交但持久化未确认，请核对原状态：%w", err)
	}
	if err = store.checkpoint("selector-committed"); err != nil {
		return err
	}
	return nil
}

// Data installation does not start services, mutate Nginx, change an app's
// installed version, or remove prior data. Published capsules are immutable;
// the only replaceable record is the explicitly selected, root-private pointer.
func (store statisticsGeoStore) install(ctx context.Context, in appcatalog.GeoDataEnvelope, appSHA string) (appcatalog.GeoDataAuthority, *geodata.Snapshot, error) {
	var empty appcatalog.GeoDataAuthority
	if store.guard != nil {
		if err := store.guard(); err != nil {
			return empty, nil, err
		}
	}
	if ctx == nil || store.trust == nil || store.now == nil || store.now().Year() < 2026 {
		return empty, nil, errors.New("地理库安装环境或时钟无效")
	}
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	a, err := store.trust.VerifyGeoDataEnvelope(in, "2.6.0", appSHA, store.now(), nil)
	if err != nil {
		return empty, nil, err
	}
	root, err := store.open(true)
	if err != nil {
		return empty, nil, err
	}
	defer root.Close()
	lock, err := geoStoreLock(root.Root)
	if err != nil {
		return empty, nil, err
	}
	defer lock.Close()
	_, before, beforeIdentity, err := store.selector(root.Root)
	if err != nil {
		return empty, nil, err
	}
	names, err := store.inventory(root)
	if err != nil {
		return empty, nil, err
	}
	for _, name := range names {
		prior, err := store.authority(root.Root, name)
		if err != nil {
			return empty, nil, err
		}
		if _, err = store.trust.VerifyGeoDataEnvelope(a.Envelope(), "2.6.0", appSHA, store.now(), &prior); err != nil {
			return empty, nil, err
		}
	}
	name := geoStoreName(a)
	if _, err = root.Lstat(name); err == nil {
		a, snapshot, verified, err := store.load(ctx, root.Root, name)
		if err != nil {
			return empty, nil, err
		}
		if err = store.publishSelection(ctx, root, name, before, beforeIdentity, verified); err != nil {
			snapshot.Close()
			return empty, nil, err
		}
		return a, snapshot, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, nil, err
	}
	if len(names) >= 8 {
		return empty, nil, errors.New("地理库保留副本达到8份；未删除旧库，请先核对保留策略")
	}
	stage := ".stage-" + core.ID()
	if err = root.Mkdir(stage, 0700); err != nil {
		return empty, nil, err
	}
	if err = ruleFeedStoreSync(root.Root); err != nil {
		return empty, nil, err
	}
	if err = store.checkpoint("stage-created"); err != nil {
		return empty, nil, err
	}
	child, err := root.OpenRoot(stage)
	if err != nil {
		return empty, nil, err
	}
	defer child.Close()
	envelope, err := json.Marshal(a.Envelope())
	if err != nil {
		return empty, nil, err
	}
	if err = ruleFeedStoreWrite(child, "envelope.json", envelope, 0600); err != nil {
		return empty, nil, err
	}
	if err = ruleFeedStoreWrite(child, "NOTICE.txt", statisticsGeoNotice(a), 0600); err != nil {
		return empty, nil, err
	}
	f, err := child.OpenFile("database.mmdb.gz", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return empty, nil, err
	}
	defer f.Close()
	if err = store.trust.DownloadGeoDatabaseFile(ctx, a, f); err != nil {
		return empty, nil, err
	}
	if err = f.Sync(); err != nil {
		return empty, nil, err
	}
	if err = store.checkpoint("download-complete"); err != nil {
		return empty, nil, err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return empty, nil, err
	}
	verified, err := f.Stat()
	if err != nil || !moduleRecordInfo(verified, false, false) {
		return empty, nil, errors.New("地理库暂存数据身份异常")
	}
	snapshot, err := geodata.Open(ctx, a.Data(), f)
	if err != nil {
		return empty, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			snapshot.Close()
		}
	}()
	if err = store.checkpoint("database-verified"); err != nil {
		return empty, nil, err
	}
	after, statErr := f.Stat()
	visible, visibleErr := child.Lstat("database.mmdb.gz")
	if statErr != nil || visibleErr != nil || !geoStoreStableInfo(verified, after) || !geoStoreStableInfo(verified, visible) {
		return empty, nil, errors.New("地理库验证后暂存数据发生变化，未发布")
	}
	if err = ruleFeedStoreSync(child); err != nil {
		return empty, nil, err
	}
	if !root.current() || ctx.Err() != nil {
		return empty, nil, errors.New("地理库发布前目录身份改变")
	}
	dir, err := root.Open(".")
	if err != nil {
		return empty, nil, err
	}
	err = unix.Renameat2(int(dir.Fd()), stage, int(dir.Fd()), name, unix.RENAME_NOREPLACE)
	dir.Close()
	if err != nil {
		return empty, nil, err
	}
	if err = ruleFeedStoreSync(root.Root); err != nil {
		return empty, nil, err
	}
	if err = store.checkpoint("capsule-published"); err != nil {
		return empty, nil, err
	}
	if err = store.publishSelection(ctx, root, name, before, beforeIdentity, verified); err != nil {
		return empty, nil, err
	}
	keep = true
	return a, snapshot, nil
}

// Explicit rollback selects only an independently signed retained capsule.
// Newer immutable releases stay in history and still block replay of older
// installation catalogs; rollback cannot lower the channel's high-water mark.
func (store statisticsGeoStore) rollback(ctx context.Context, name string) (*geodata.Snapshot, error) {
	if store.guard != nil {
		if err := store.guard(); err != nil {
			return nil, err
		}
	}
	if ctx == nil {
		return nil, errors.New("地理库回滚环境无效")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !statisticsGeoName.MatchString(name) {
		return nil, errors.New("回滚数据身份无效")
	}
	root, err := store.open(false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := geoStoreLock(root.Root)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if _, err = store.inventory(root); err != nil {
		return nil, err
	}
	_, before, beforeIdentity, err := store.selector(root.Root)
	if err != nil {
		return nil, err
	}
	_, snapshot, verified, err := store.load(ctx, root.Root, name)
	if err != nil {
		return nil, err
	}
	if err = store.publishSelection(ctx, root, name, before, beforeIdentity, verified); err != nil {
		snapshot.Close()
		return nil, err
	}
	return snapshot, nil
}
