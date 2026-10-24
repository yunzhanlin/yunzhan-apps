//go:build linux

package executor

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const intrusionConfigurationEntries = 512
const intrusionConfigurationFileBytes = 256 << 10
const intrusionConfigurationTotalBytes = 8 << 20

type intrusionConfigurationEntry struct {
	Kind                  string
	Mode                  uint32
	UID, GID              uint32
	Device, Inode         uint64
	Size                  int64
	ModifiedNS, ChangedNS int64
	SHA256                string
}
type intrusionConfigurationTree struct {
	Entries map[string]intrusionConfigurationEntry
	Bytes   int64
}

// Persisted inventories are comparison evidence only: no recorded name can
// become a write path or choose an executable. Still reject partial/forged
// inventories before a durable record can authorize ANY fixed-path mutation.
func intrusionConfigurationTreeValidate(tree intrusionConfigurationTree, jail hardeningJournalFile) error {
	if len(tree.Entries) < 2 || len(tree.Entries) > intrusionConfigurationEntries || hardeningJournalStoredFile(jail, false) != nil {
		return errors.New("入侵防护事务缺少完整可信配置目录基线")
	}
	var total int64
	identities := map[[2]uint64]bool{}
	for name, value := range tree.Entries {
		if !utf8.ValidString(name) || name == ".." || name != "." && (path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00\r\n") || len(name) > 1024 || len(strings.Split(name, "/")) > 8) {
			return errors.New("入侵防护目录基线含不规范或越界的比较名称")
		}
		for _, part := range strings.Split(name, "/") {
			if len(part) > 255 {
				return errors.New("入侵防护目录基线名称超限")
			}
		}
		mode := os.FileMode(value.Mode)
		identity := [2]uint64{value.Device, value.Inode}
		if identities[identity] {
			return errors.New("入侵防护目录基线存在重复物理身份")
		}
		identities[identity] = true
		if value.UID != uint32(os.Geteuid()) || value.Inode == 0 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeSymlink) != 0 || mode.Perm()&0022 != 0 {
			return errors.New("入侵防护目录基线身份、权限或文件身份无法核对")
		}
		if name != "." {
			parent, ok := tree.Entries[path.Dir(name)]
			if !ok || parent.Kind != "directory" {
				return errors.New("入侵防护目录基线缺少完整父级")
			}
		}
		switch value.Kind {
		case "directory":
			if mode != os.ModeDir|mode.Perm() || mode.Perm()&0700 != 0700 || value.Size != 0 || value.SHA256 != "" || value.ModifiedNS != 0 || value.ChangedNS != 0 {
				return errors.New("入侵防护目录比较基线含未知字段")
			}
		case "file":
			if mode != mode.Perm() || value.Size < 0 || value.Size > intrusionConfigurationFileBytes || len(value.SHA256) != 64 || strings.ToLower(value.SHA256) != value.SHA256 {
				return errors.New("入侵防护文件比较基线含未知类型或容量")
			}
			if raw, err := hex.DecodeString(value.SHA256); err != nil || len(raw) != 32 {
				return errors.New("入侵防护文件比较基线完整摘要无效")
			}
			total += value.Size
		default:
			return errors.New("入侵防护目录比较基线含未知路径类型")
		}
	}
	if root, ok := tree.Entries["."]; !ok || root.Kind != "directory" || total != tree.Bytes || total > intrusionConfigurationTotalBytes {
		return errors.New("入侵防护目录比较基线的根身份或总容量不完整")
	}
	leaf, ok := tree.Entries["jail.d/panel-intrusion.local"]
	if parent, exists := tree.Entries["jail.d"]; !exists || parent.Kind != "directory" {
		return errors.New("入侵防护原配置缺少可信受管文件父目录；未自动创建或修复")
	}
	if !jail.Exists {
		if ok {
			return errors.New("入侵防护已知缺失与实际目录基线冲突；未接管未登记文件")
		}
		return nil
	}
	if !ok || leaf.Kind != "file" || leaf.Mode != jail.Mode || leaf.UID != jail.Owner.UID || leaf.GID != jail.Owner.GID || leaf.Size != int64(len(jail.Data)) || leaf.SHA256 != core.Hash(string(jail.Data)) {
		return errors.New("入侵防护原 Jail 与完整目录基线不属于同一观察")
	}
	return nil
}

func intrusionConfigurationInfo(info os.FileInfo, directory bool) (intrusionConfigurationEntry, error) {
	var out intrusionConfigurationEntry
	if info == nil {
		return out, errors.New("入侵防护配置路径身份缺失")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 || directory && !info.IsDir() || !directory && (!info.Mode().IsRegular() || st.Nlink != 1) {
		return out, errors.New("入侵防护配置目录树含不受信的路径、所有者、权限或链接；未修复")
	}
	out = intrusionConfigurationEntry{Kind: "file", Mode: uint32(info.Mode()), UID: st.Uid, GID: st.Gid, Device: uint64(st.Dev), Inode: st.Ino, Size: info.Size(), ModifiedNS: info.ModTime().UnixNano(), ChangedNS: st.Ctim.Sec*1000000000 + st.Ctim.Nsec}
	if directory {
		if info.Mode().Perm()&0700 != 0700 {
			return out, errors.New("入侵防护配置目录缺少实际读取权限")
		}
		// A scoped atomic replacement legitimately changes the containing
		// directory's timestamps/size, not its identity or entry inventory.
		out.Kind = "directory"
		out.Size = 0
		out.ModifiedNS = 0
		out.ChangedNS = 0
	} else if out.Size < 0 || out.Size > intrusionConfigurationFileBytes {
		return out, errors.New("入侵防护配置文件超出固定观察容量")
	}
	return out, nil
}

func intrusionConfigurationDirectoryNames(root *os.Root) ([]string, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(intrusionConfigurationEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > intrusionConfigurationEntries {
		return nil, errors.New("入侵防护配置目录超过固定条目范围")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !utf8.ValidString(name) || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") || len(name) > 255 {
			return nil, errors.New("入侵防护配置目录含未知名称，未忽略")
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

func intrusionConfigurationReadFile(root *os.Root, name string) (intrusionConfigurationEntry, error) {
	entry, _, err := intrusionConfigurationReadFileData(root, name)
	return entry, err
}

// Return bytes ONLY after the same original bounded descriptor/named-file CAS.
// The directory inventory caller still receives only metadata and full hash.
func intrusionConfigurationReadFileData(root *os.Root, name string) (intrusionConfigurationEntry, []byte, error) {
	var empty intrusionConfigurationEntry
	info, err := root.Lstat(name)
	if err != nil {
		return empty, nil, err
	}
	before, err := intrusionConfigurationInfo(info, false)
	if err != nil {
		return empty, nil, err
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return empty, nil, err
	}
	initial, err := intrusionConfigurationInfo(opened, false)
	if err != nil || initial != before {
		return empty, nil, errors.New("入侵防护配置文件打开期间身份改变")
	}
	raw, err := io.ReadAll(io.LimitReader(f, intrusionConfigurationFileBytes+1))
	if err != nil {
		return empty, nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return empty, nil, err
	}
	last, err := intrusionConfigurationInfo(after, false)
	if err != nil {
		return empty, nil, err
	}
	visible, err := root.Lstat(name)
	if err != nil {
		return empty, nil, err
	}
	named, err := intrusionConfigurationInfo(visible, false)
	if err != nil || last != before || named != before || int64(len(raw)) != before.Size {
		return empty, nil, errors.New("入侵防护配置文件读取期间内容或命名身份改变")
	}
	before.SHA256 = core.Hash(string(raw))
	return before, raw, nil
}

func (s *Service) readIntrusionConfigurationTree(ctx context.Context) (intrusionConfigurationTree, error) {
	return s.readIntrusionConfigurationTreeAt(ctx, s.systemPath("/etc/fail2ban"))
}

// Internal fixed-source/candidate roots only. No HTTP argument or journal
// entry chooses this root; the same no-link, ownership and complete limits
// apply to candidate inventory/cleanup as to the installed configuration.
func (s *Service) readIntrusionConfigurationTreeAt(ctx context.Context, base string) (intrusionConfigurationTree, error) {
	out := intrusionConfigurationTree{Entries: map[string]intrusionConfigurationEntry{}}
	if err := s.wafOwnedDirectory(base, false); err != nil {
		return out, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return out, err
	}
	defer root.Close()
	var visit func(*os.Root, string, int) error
	visit = func(directory *os.Root, relative string, depth int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if depth > 8 || len(out.Entries) >= intrusionConfigurationEntries {
			return errors.New("入侵防护配置目录树超出固定深度或容量")
		}
		opened, err := directory.Stat(".")
		if err != nil {
			return err
		}
		entry, err := intrusionConfigurationInfo(opened, true)
		if err != nil {
			return err
		}
		visible, err := os.Lstat(directory.Name())
		if err != nil {
			return err
		}
		named, err := intrusionConfigurationInfo(visible, true)
		if err != nil || named != entry {
			return errors.New("入侵防护配置目录命名身份改变")
		}
		names, err := intrusionConfigurationDirectoryNames(directory)
		if err != nil {
			return err
		}
		out.Entries[relative] = entry
		for _, name := range names {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if len(out.Entries) >= intrusionConfigurationEntries {
				return errors.New("入侵防护配置目录树超过固定条目范围")
			}
			logical := name
			if relative != "." {
				logical = relative + "/" + name
			}
			info, err := directory.Lstat(name)
			if err != nil {
				return err
			}
			if info.IsDir() {
				before, err := intrusionConfigurationInfo(info, true)
				if err != nil {
					return err
				}
				child, err := directory.OpenRoot(name)
				if err != nil {
					return err
				}
				err = visit(child, logical, depth+1)
				child.Close()
				if err != nil {
					return err
				}
				if out.Entries[logical] != before {
					return errors.New("入侵防护子目录打开期间身份改变")
				}
			} else {
				value, err := intrusionConfigurationReadFile(directory, name)
				if err != nil {
					return err
				}
				out.Bytes += value.Size
				if out.Bytes > intrusionConfigurationTotalBytes {
					return errors.New("入侵防护配置目录树超过固定字节容量")
				}
				out.Entries[logical] = value
			}
		}
		afterNames, err := intrusionConfigurationDirectoryNames(directory)
		if err != nil {
			return err
		}
		after, err := directory.Stat(".")
		if err != nil {
			return err
		}
		last, err := intrusionConfigurationInfo(after, true)
		if err != nil {
			return err
		}
		visible, err = os.Lstat(directory.Name())
		if err != nil {
			return err
		}
		named, err = intrusionConfigurationInfo(visible, true)
		// During one read even a same-name replacement must not be hidden by
		// a stable final listing. Directory ctime/mtime expose that torn read.
		oldStat, ok := opened.Sys().(*syscall.Stat_t)
		newStat, newOK := after.Sys().(*syscall.Stat_t)
		if err != nil || last != entry || named != entry || !slices.Equal(names, afterNames) || !ok || !newOK || oldStat.Mtim != newStat.Mtim || oldStat.Ctim != newStat.Ctim {
			return errors.New("入侵防护配置目录在完整观察期间改变")
		}
		return nil
	}
	if err = visit(root, ".", 0); err != nil {
		return out, err
	}
	if err = s.wafOwnedDirectory(base, false); err != nil {
		return out, err
	}
	return out, nil
}

// Only the exact declared managed Jail can be created, replaced or removed. Every
// other file and directory identity, content, metadata and name is retained.
// This comparison is NOT permission to write and never repairs foreign data.
func intrusionConfigurationTreeAfterJail(before, after intrusionConfigurationTree, expected hardeningJournalFile) error {
	const name = "jail.d/panel-intrusion.local"
	if hardeningJournalStoredFile(expected, false) != nil {
		return errors.New("入侵防护配置目录树或受管文件目标无法核对")
	}
	wantedCount, wantedBytes := len(before.Entries), before.Bytes
	if old, exists := before.Entries[name]; exists {
		wantedCount--
		wantedBytes -= old.Size
	}
	if expected.Exists {
		wantedCount++
		wantedBytes += int64(len(expected.Data))
	}
	if len(after.Entries) != wantedCount || after.Bytes != wantedBytes {
		return errors.New("入侵防护目录条目或字节变化超出固定受管文件")
	}
	current, exists := after.Entries[name]
	if expected.Exists != exists || expected.Exists && (current.Kind != "file" || current.Mode != expected.Mode || current.UID != expected.Owner.UID || current.GID != expected.Owner.GID || current.Size != int64(len(expected.Data)) || current.SHA256 != core.Hash(string(expected.Data))) {
		return errors.New("入侵防护受管 Jail 不属于原事务明确目标")
	}
	for path, entry := range before.Entries {
		if path == name {
			continue
		}
		if got, exists := after.Entries[path]; !exists || !reflect.DeepEqual(entry, got) {
			return errors.New("入侵防护非受管配置发生改变，未执行重载或覆盖")
		}
	}
	return nil
}
