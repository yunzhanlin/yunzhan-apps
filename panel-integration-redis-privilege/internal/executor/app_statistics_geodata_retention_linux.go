//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

const statisticsGeoDataActiveMax = 8
const statisticsGeoDataArchiveMax = 24

// Fixed private child within the existing data-only writable bind mount.
// Separate ReadWritePaths bind mounts would make rename return EXDEV even on
// the same disk. No broader executor parent becomes writable to the worker.
// No caller, manifest or UI field can supply a destination path.
func (store statisticsGeoStore) archiveStore() statisticsGeoStore {
	out := store
	out.base = filepath.Join(store.base, ".archive")
	return out
}
func (store statisticsGeoStore) archivedInventory() (*statisticsGeoDirectory, []string, error) {
	// The archive is a fixed child of the active store. On first use that
	// entire store is legitimately absent. Authenticate its existing parent
	// chain through the normal read-only opener before treating this as empty;
	// do not create directories, hide an unsafe parent or relax child checks.
	active, err := store.open(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, []string{}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer active.Close()
	root, err := store.archiveStore().open(false)
	if errors.Is(err, os.ErrNotExist) {
		if !active.current() {
			return nil, nil, errors.New("活动目录在归档缺失核对期间变化；未返回空库存")
		}
		return nil, []string{}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	bad := func(err error) (*statisticsGeoDirectory, []string, error) { root.Close(); return nil, nil, err }
	dir, err := root.Open(".")
	if err != nil {
		return bad(err)
	}
	entries, err := dir.ReadDir(statisticsGeoDataArchiveMax + 1)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > statisticsGeoDataArchiveMax {
		return bad(errors.New("地域数据归档库存超过24份；未自动清理"))
	}
	names := []string{}
	for _, entry := range entries {
		info, e := root.Lstat(entry.Name())
		if e != nil || !statisticsGeoName.MatchString(entry.Name()) || !moduleRecordInfo(info, true, false) {
			return bad(errors.New("地域数据归档含未知或不受信条目，未接管"))
		}
		names = append(names, entry.Name())
	}
	if !active.current() || !root.current() {
		return bad(errors.New("地域数据归档目录读取期间变化"))
	}
	sort.Strings(names)
	return root, names, nil
}

// A verified highest active release stays in the active store even after
// rollback. Keeping that signed anchor avoids weakening install high-water
// semantics or relying on an unsigned cleanup counter.
func (store statisticsGeoStore) storedRows(root *statisticsGeoDirectory, selected statisticsGeoSelector) ([]core.StatisticsGeoStored, error) {
	names, err := store.inventory(root)
	if err != nil {
		return nil, err
	}
	if len(names) > statisticsGeoDataActiveMax {
		return nil, errors.New("地域数据活动副本超过8份")
	}
	archive, archived, err := store.archivedInventory()
	if err != nil {
		return nil, err
	}
	if archive != nil {
		defer archive.Close()
	}
	if len(names) == 0 && len(archived) > 0 {
		return nil, errors.New("归档存在但活动签名锚点丢失；未猜测防重放状态")
	}
	out := []core.StatisticsGeoStored{}
	seen := map[string]bool{}
	highest := ""
	for _, name := range names {
		a, err := store.authority(root.Root, name)
		if err != nil {
			return nil, err
		}
		release := a.Data().Manifest().Release
		if release > highest {
			highest = release
		}
		seen[name] = true
		out = append(out, core.StatisticsGeoStored{Release: release, ManifestSHA: a.Data().SHA256(), AppSHA: a.AppSHA256(), Selected: name == selected.Dataset, Previous: name == selected.Previous})
	}
	for i := range out {
		out[i].HighWater = out[i].Release == highest
	}
	for _, name := range archived {
		if seen[name] {
			return nil, errors.New("活动与归档含相同地域副本；不覆盖双方原证据")
		}
		a, err := store.authority(archive.Root, name)
		if err != nil || a.Data().Manifest().Release > highest || name == selected.Dataset || name == selected.Previous {
			return nil, errors.New("地域归档签名、选择或防重放锚点不同")
		}
		out = append(out, core.StatisticsGeoStored{Release: a.Data().Manifest().Release, ManifestSHA: a.Data().SHA256(), AppSHA: a.AppSHA256(), Archived: true})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Release != out[j].Release {
			return out[i].Release < out[j].Release
		}
		return out[i].ManifestSHA < out[j].ManifestSHA
	})
	return out, nil
}

func geoDatasetFiles(root *os.Root, name string) (map[string]os.FileInfo, error) {
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	defer child.Close()
	out := map[string]os.FileInfo{}
	for _, leaf := range []string{"envelope.json", "database.mmdb.gz", "NOTICE.txt"} {
		info, e := child.Lstat(leaf)
		if e != nil || !moduleRecordInfo(info, false, false) {
			return nil, errors.New("地域副本原文件身份异常")
		}
		out[leaf] = info
	}
	return out, nil
}
func geoDatasetSameFiles(before, after map[string]os.FileInfo) bool {
	if len(before) != 3 || len(after) != 3 {
		return false
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			return false
		}
	}
	return true
}

// Complete signed gzip/raw/database validation runs in the existing bounded
// native background worker. Moves preserve all original bytes and inodes.
// Restoring a copy never selects it; rollback remains a separate explicit job.
func (store statisticsGeoStore) maintain(ctx context.Context, action, name string) error {
	if ctx == nil || ctx.Err() != nil || action != "archive" && action != "restore" || !statisticsGeoName.MatchString(name) {
		return errors.New("地域副本维护的固定动作或身份无效")
	}
	if store.guard != nil {
		if err := store.guard(); err != nil {
			return err
		}
	}
	active, err := store.open(false)
	if err != nil {
		return err
	}
	defer active.Close()
	lock, err := geoStoreLock(active.Root)
	if err != nil {
		return err
	}
	defer lock.Close()
	selected, before, selectorIdentity, err := store.selector(active.Root)
	if err != nil {
		return err
	}
	rows, err := store.storedRows(active, selected)
	if err != nil {
		return err
	}
	var original *core.StatisticsGeoStored
	activeCount, archiveCount := 0, 0
	for i, row := range rows {
		if row.Archived {
			archiveCount++
		} else {
			activeCount++
		}
		if geodata.Channel+"-"+row.Release+"-"+row.ManifestSHA == name {
			original = &rows[i]
		}
	}
	if original == nil {
		return errors.New("所选原地域副本缺失")
	}
	if action == "archive" && (original.Selected || original.Previous || original.HighWater) {
		return errors.New("当前、上一份和最高签名月份的防重放锚点必须保留，禁止归档")
	}
	replayed := action == "archive" && original.Archived || action == "restore" && !original.Archived
	if !replayed && action == "archive" && archiveCount >= statisticsGeoDataArchiveMax {
		return errors.New("地域副本归档区已满24份；未删除原数据")
	}
	if !replayed && action == "restore" && activeCount >= statisticsGeoDataActiveMax {
		return errors.New("活动区已满8份，请先明确归档非受保护旧副本；未选择或删除数据")
	}
	archiveStore := store.archiveStore()
	archive, _, err := store.archivedInventory()
	if err != nil {
		return err
	}
	if archive != nil {
		defer archive.Close()
	}
	if archive == nil && action == "archive" && !replayed {
		archive, err = archiveStore.open(true)
		if err != nil {
			return err
		}
		defer archive.Close()
		parent, e := os.OpenRoot(filepath.Dir(archiveStore.base))
		if e != nil {
			return e
		}
		e = ruleFeedStoreSync(parent)
		parent.Close()
		if e != nil {
			return e
		}
	}
	source, destination := active, archive
	loadStore := store
	if original.Archived {
		source = archive
		loadStore = archiveStore
	}
	if action == "restore" {
		destination = active
	}
	if source == nil || !replayed && destination == nil {
		return errors.New("地域副本交接目录不可核对")
	}
	identities, err := geoDatasetFiles(source.Root, name)
	if err != nil {
		return err
	}
	a, snapshot, verified, err := loadStore.load(ctx, source.Root, name)
	if err != nil {
		return err
	}
	snapshot.Close()
	if a.Data().SHA256() != original.ManifestSHA || a.AppSHA256() != original.AppSHA {
		return errors.New("原地域副本独立签名绑定不同")
	}
	if replayed {
		if err = ruleFeedStoreSync(active.Root); err != nil {
			return err
		}
		if archive != nil {
			return ruleFeedStoreSync(archive.Root)
		}
		return nil
	}
	child, err := source.OpenRoot(name)
	if err != nil {
		return err
	}
	defer child.Close()
	directoryInfo, err := child.Stat(".")
	if err != nil {
		return err
	}
	for _, leaf := range []string{"envelope.json", "database.mmdb.gz", "NOTICE.txt"} {
		f, e := child.OpenFile(leaf, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
	}
	if err = ruleFeedStoreSync(child); err != nil {
		return err
	}
	if err = store.checkpoint("dataset-before-rename"); err != nil {
		return err
	}
	afterFiles, err := geoDatasetFiles(source.Root, name)
	_, current, currentIdentity, selectorErr := store.selector(active.Root)
	visible, visibleErr := source.Lstat(name)
	if err != nil || selectorErr != nil || !bytes.Equal(before, current) || !geoSelectorSameIdentity(selectorIdentity, currentIdentity) || !geoDatasetSameFiles(identities, afterFiles) || visibleErr != nil || !os.SameFile(directoryInfo, visible) || !source.current() || !destination.current() || !loadStore.publicationCurrent(ctx, source, name, verified) {
		return errors.New("地域副本、选择或安装身份交接前变化，未维护")
	}
	src, err := source.Open(".")
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := destination.Open(".")
	if err != nil {
		return err
	}
	defer dst.Close()
	if err = unix.Renameat2(int(src.Fd()), name, int(dst.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err = store.checkpoint("dataset-after-rename"); err != nil {
		return errors.New("地域副本可能已交接，请用原身份核对库存；原文件未删除，选择未切换")
	}
	if src.Sync() != nil || dst.Sync() != nil {
		return errors.New("地域副本已交接但持久性未核对；使用原身份核对，不生成另一份数据")
	}
	if err = store.checkpoint("dataset-after-sync"); err != nil {
		return err
	}
	finalFiles, err := geoDatasetFiles(destination.Root, name)
	newInfo, identityErr := destination.Lstat(name)
	_, current, currentIdentity, selectorErr = store.selector(active.Root)
	if err != nil || identityErr != nil || selectorErr != nil || !os.SameFile(directoryInfo, newInfo) || !geoDatasetSameFiles(identities, finalFiles) || !bytes.Equal(before, current) || !geoSelectorSameIdentity(selectorIdentity, currentIdentity) || !source.current() || !destination.current() {
		return errors.New("地域副本交接后的原文件或选择不能核对")
	}
	return nil
}
