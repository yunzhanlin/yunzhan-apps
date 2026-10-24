//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const intrusionRemovalCacheName = ".intrusion-removal-candidates"

var intrusionRemovalCopyName = regexp.MustCompile(`^candidate-[a-f0-9]{32}$`)

type intrusionRemovalCopy struct {
	cache *os.Root
	root  *os.Root
	name  string
	tree  intrusionConfigurationTree
}

func intrusionRemovalPrivateDirectory(info os.FileInfo) bool {
	entry, err := intrusionConfigurationInfo(info, true)
	return err == nil && entry.Mode == uint32(os.ModeDir|0700)
}

// All cache writes are below the already trusted security root, while the
// original named app lock is held. The cache is private even when that root
// legitimately has the shared 0750/0755 mode. Existing paths are never repaired.
func (s *Service) intrusionRemovalCache(lock *os.File) (*os.Root, error) {
	if err := s.intrusionJournalRequireLock(lock); err != nil {
		return nil, err
	}
	parent, err := s.intrusionJournalRoot()
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := parent.Mkdir(intrusionRemovalCacheName, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := parent.Lstat(intrusionRemovalCacheName)
	if err != nil || !intrusionRemovalPrivateDirectory(info) || !s.softwareManifestAnchorCurrent(parent) {
		return nil, errors.New("卸载候选缓存目录身份或私有权限未知；未修复")
	}
	root, err := parent.OpenRoot(intrusionRemovalCacheName)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !intrusionRemovalPrivateDirectory(opened) {
		root.Close()
		return nil, errors.New("卸载候选缓存打开期间身份改变")
	}
	names, err := intrusionConfigurationDirectoryNames(root)
	if err != nil || len(names) >= 16 {
		root.Close()
		return nil, errors.New("卸载候选私有证据超过固定容量；未删除旧证据")
	}
	for _, name := range names {
		entry, err := root.Lstat(name)
		if err != nil || !intrusionRemovalCopyName.MatchString(name) || !intrusionRemovalPrivateDirectory(entry) {
			root.Close()
			return nil, errors.New("卸载候选缓存含未知对象；未忽略、删除或接管")
		}
	}
	return root, nil
}

func (s *Service) intrusionRemovalCopyCurrent(lock *os.File, copy *intrusionRemovalCopy) error {
	if copy == nil || copy.cache == nil || copy.root == nil || !intrusionRemovalCopyName.MatchString(copy.name) {
		return errors.New("卸载候选缺少本次私有副本身份")
	}
	if err := s.intrusionJournalRequireLock(lock); err != nil {
		return err
	}
	parent, err := s.intrusionJournalRoot()
	if err != nil {
		return err
	}
	defer parent.Close()
	named, err := parent.Lstat(intrusionRemovalCacheName)
	opened, openErr := copy.cache.Stat(".")
	if err != nil || openErr != nil || !os.SameFile(named, opened) || !intrusionRemovalPrivateDirectory(named) || !s.softwareManifestAnchorCurrent(parent) {
		return errors.New("卸载候选原缓存命名身份改变")
	}
	named, err = copy.cache.Lstat(copy.name)
	opened, openErr = copy.root.Stat(".")
	if err != nil || openErr != nil || !os.SameFile(named, opened) || !intrusionRemovalPrivateDirectory(named) || !intrusionRemovalPrivateDirectory(opened) {
		return errors.New("卸载候选原副本命名身份改变")
	}
	return nil
}

// Build a private test-only replica of the complete verified configuration,
// omitting ONE exact managed Jail. Never remove/edit the installed config to
// discover defaults, copy an old snapshot over it, or send a dump to a daemon.
// On a partial-copy error the bounded private attempt stays evidence; no old
// candidate is reused/promoted or broadly cleaned up.
func (s *Service) newIntrusionRemovalCopy(ctx context.Context, lock *os.File, before intrusionConfigurationTree, jail hardeningJournalFile) (result *intrusionRemovalCopy, copyErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !jail.Exists || intrusionConfigurationTreeValidate(before, jail) != nil {
		return nil, errors.New("卸载候选缺少实际已受管 Jail 和完整配置基线")
	}
	if err := s.intrusionJournalRequireLock(lock); err != nil {
		return nil, err
	}
	actual, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(actual, before) {
		return nil, errors.New("卸载候选源配置与原完整观察不同；未复制或修复")
	}
	source, err := os.OpenRoot(s.systemPath("/etc/fail2ban"))
	if err != nil {
		return nil, err
	}
	defer source.Close()
	opened, err := source.Stat(".")
	if err != nil {
		return nil, err
	}
	identity, err := intrusionConfigurationInfo(opened, true)
	if err != nil || identity != before.Entries["."] {
		return nil, errors.New("卸载候选源配置根目录在打开期间改变")
	}
	cache, err := s.intrusionRemovalCache(lock)
	if err != nil {
		return nil, err
	}
	copy := &intrusionRemovalCopy{cache: cache, name: "candidate-" + core.ID()}
	defer func() {
		if copyErr != nil {
			if copy.root != nil {
				copy.root.Close()
			}
			copy.cache.Close()
		}
	}()
	if err := cache.Mkdir(copy.name, 0700); err != nil {
		return nil, err
	}
	copy.root, err = cache.OpenRoot(copy.name)
	if err != nil {
		return nil, err
	}
	if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(before.Entries))
	for name := range before.Entries {
		if name != "." && name != "jail.d/panel-intrusion.local" {
			names = append(names, name)
		}
	}
	slices.Sort(names) // Parents precede their descendants; no caller-chosen paths.
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
			return nil, err
		}
		wanted := before.Entries[name]
		if wanted.Kind == "directory" {
			info, err := source.Lstat(name)
			if err != nil {
				return nil, err
			}
			current, err := intrusionConfigurationInfo(info, true)
			if err != nil || current != wanted {
				return nil, errors.New("卸载候选源目录在复制期间改变")
			}
			if err := copy.root.Mkdir(name, 0700); err != nil {
				return nil, err
			}
			continue
		}
		parent, err := source.OpenRoot(path.Dir(name))
		if err != nil {
			return nil, err
		}
		entry, raw, err := intrusionConfigurationReadFileData(parent, path.Base(name))
		parent.Close()
		if err != nil || entry != wanted {
			return nil, errors.New("卸载候选源文件身份、内容或权限已改变；未使用混合副本")
		}
		file, err := copy.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
		if err != nil {
			return nil, err
		}
		if err = file.Chmod(0600); err == nil {
			var n int
			n, err = file.Write(raw)
			if err == nil && n != len(raw) {
				err = io.ErrShortWrite
			}
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		entry, data, err := intrusionConfigurationReadFileData(copy.root, name)
		if err != nil || entry.SHA256 != wanted.SHA256 || entry.Size != wanted.Size || len(data) != len(raw) || entry.Mode != 0600 {
			return nil, errors.New("卸载候选副本写入后不能完整核对；保留私有证据")
		}
	}
	actual, err = s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(before, actual) {
		return nil, errors.New("卸载候选复制期间源完整配置改变；未执行或采用配置流")
	}
	copy.tree, err = s.readIntrusionConfigurationTreeAt(ctx, copy.root.Name())
	if err != nil || len(copy.tree.Entries) != len(before.Entries)-1 || copy.tree.Bytes != before.Bytes-int64(len(jail.Data)) {
		return nil, errors.New("卸载候选副本的完整条目或字节范围无法核对")
	}
	if _, exists := copy.tree.Entries["jail.d/panel-intrusion.local"]; exists {
		return nil, errors.New("卸载候选错误包含受管 Jail")
	}
	for _, name := range names {
		wanted, actual := before.Entries[name], copy.tree.Entries[name]
		if wanted.Kind != actual.Kind || wanted.Kind == "file" && (actual.Mode != 0600 || actual.Size != wanted.Size || actual.SHA256 != wanted.SHA256) || wanted.Kind == "directory" && actual.Mode != uint32(os.ModeDir|0700) {
			return nil, errors.New("卸载候选副本不再完整匹配原逐文件内容；未采用外部替换")
		}
	}
	if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
		return nil, err
	}
	return copy, nil
}

// Cleanup targets ONLY this process's NEW verified replica and exact names.
// Unknown files/links/replacements are retained, never followed or deleted.
// No recursive deletion, installed config path or historical candidate is used.
func (s *Service) closeIntrusionRemovalCopy(ctx context.Context, lock *os.File, copy *intrusionRemovalCopy) error {
	if copy == nil || copy.root == nil || copy.cache == nil {
		return errors.New("卸载候选清理缺少原副本句柄")
	}
	defer copy.root.Close()
	defer copy.cache.Close()
	if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
		return err
	}
	actual, err := s.readIntrusionConfigurationTreeAt(ctx, copy.root.Name())
	if err != nil || !reflect.DeepEqual(actual, copy.tree) {
		return errors.New("卸载候选副本出现外部变化；保留私有证据，未清理未知对象")
	}
	names := make([]string, 0, len(copy.tree.Entries))
	for name := range copy.tree.Entries {
		if name != "." {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	slices.Reverse(names) // Exact children before their known empty parents.
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
			return err
		}
		wanted := copy.tree.Entries[name]
		var entry intrusionConfigurationEntry
		if wanted.Kind == "file" {
			entry, _, err = intrusionConfigurationReadFileData(copy.root, name)
		} else {
			var info os.FileInfo
			info, err = copy.root.Lstat(name)
			if err == nil {
				entry, err = intrusionConfigurationInfo(info, true)
			}
		}
		if err != nil || entry != wanted {
			return errors.New("卸载候选清理前原条目已改变；未删除替换对象")
		}
		if err := copy.root.Remove(filepath.FromSlash(name)); err != nil {
			return err
		}
	}
	if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
		return err
	}
	return copy.cache.Remove(copy.name)
}
