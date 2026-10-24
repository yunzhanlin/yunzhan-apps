// Package diskusage contains read-only kernel filesystem accounting primitives.
// Host scans must be run by an isolated bounded worker, never while holding the
// executor's general application mutex. This package starts no worker itself.
package diskusage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MountInfoBytesMax = 4 << 20
const MountCountMax = 16384
const mountLineBytesMax = 65536

var ErrMountInventory = errors.New("挂载清单不完整、格式错误或超过上限；未使用部分清单开始扫描")

// IDs remain strings in the wire format, so a browser never rounds a kernel
// identifier. Mount source and options can contain credentials. They are never
// retained, returned, logged, or included in the public binding digest.
type Mount struct {
	ID         string `json:"mount_id"`
	ParentID   string `json:"parent_id"`
	Major      uint32 `json:"device_major"`
	Minor      uint32 `json:"device_minor"`
	Root       string `json:"filesystem_root"`
	Point      string `json:"mount_point"`
	Filesystem string `json:"filesystem"`
	ReadOnly   bool   `json:"mount_read_only"`
	Class      string `json:"filesystem_class"`
	Actionable bool   `json:"path_actionable"`
	Stacked    bool   `json:"stacked_mount_point"`
	BindingSHA string `json:"binding_sha256"`
	rawRoot    string
	rawPoint   string
}

type Inventory struct {
	Format             int     `json:"format"`
	Mounts             []Mount `json:"mounts"`
	BindingSHA         string  `json:"binding_sha256"`
	MountListComplete  bool    `json:"mount_list_complete"`
	SnapshotConsistent bool    `json:"snapshot_consistent"`
}

// The initial selected-point lookup may cross mounts to reach that point.
// Refuse a known remote/userspace/unknown lookup ancestor BEFORE that lookup;
// NO_XDEV then protects every descendant. Missing/cyclic non-root ancestry is
// not a license to probe. Kernel virtual ancestors (e.g. /dev -> /dev/shm)
// may locate a local mount but are never themselves eligible scan scopes.
func (i Inventory) LocalLookup(id string) bool {
	if i.Format != 1 || !i.MountListComplete || len(i.Mounts) == 0 || len(i.Mounts) > MountCountMax {
		return false
	}
	byID := make(map[string]Mount, len(i.Mounts))
	for _, m := range i.Mounts {
		if _, duplicate := byID[m.ID]; duplicate {
			return false
		}
		byID[m.ID] = m
	}
	m, ok := byID[id]
	if !ok || filesystemClass(m.Filesystem) != "local" || m.Class != "local" {
		return false
	}
	for n := 0; n < len(i.Mounts); n++ {
		class := filesystemClass(m.Filesystem)
		if class == "remote_or_userspace" || class == "unknown" {
			return false
		}
		if m.rawPoint == "/" {
			return true
		}
		parent, ok := byID[m.ParentID]
		if !ok || parent.ID == m.ID {
			return false
		}
		m = parent
	}
	return false
}

// Decode only the four escapes emitted for mountinfo path fields. Do not use
// URL decoding, filepath.EvalSymlinks, a shell, or arbitrary octal unescaping.
// https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html
func mountUnescape(value string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			if value[i] == 0 || value[i] == '\t' || value[i] == '\n' {
				return "", false
			}
			out.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", false
		}
		switch value[i+1 : i+4] {
		case "040":
			out.WriteByte(' ')
		case "011":
			out.WriteByte('\t')
		case "012":
			out.WriteByte('\n')
		case "134":
			out.WriteByte('\\')
		default:
			return "", false
		}
		i += 3
	}
	return out.String(), true
}

func canonicalUint(value string, bits int, nonzero bool) (uint64, bool) {
	n, err := strconv.ParseUint(value, 10, bits)
	return n, err == nil && (!nonzero || n != 0) && strconv.FormatUint(n, 10) == value
}

// ValidHostPath is lexical only. A true result is never authority to scan:
// OpenMount and OpenDirectory must still bind the real held kernel mount FD.
func ValidHostPath(value string) bool {
	if value == "" || len(value) > 4096 || value[0] != '/' || !utf8.ValidString(value) || path.Clean(value) != value {
		return false
	}
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func filesystemClass(value string) string {
	switch value {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "bcachefs", "f2fs", "jfs", "nilfs2", "reiserfs", "zfs", "ufs", "hfsplus", "vfat", "msdos", "exfat", "ntfs", "ntfs3", "isofs", "udf", "overlay", "aufs", "tmpfs", "ramfs", "erofs", "squashfs", "ecryptfs":
		return "local"
	case "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "tracefs", "debugfs", "pstore", "configfs", "mqueue", "bpf", "hugetlbfs", "nsfs", "fusectl", "efivarfs", "autofs", "binfmt_misc", "rpc_pipefs", "sunrpc", "selinuxfs", "smackfs", "rootfs":
		return "kernel_virtual"
	case "nfs", "nfs4", "cifs", "smb3", "ceph", "9p", "afs", "coda", "glusterfs", "lustre", "davfs2", "fuse", "virtiofs":
		return "remote_or_userspace"
	}
	if strings.HasPrefix(value, "fuse.") {
		return "remote_or_userspace"
	}
	return "unknown"
}

// Namespace mounts can have a kernel-generated d_dname instead of an absolute
// filesystem root (e.g. net:[4026531992]). Inventory these exact nsfs identities
// without treating them as paths. Do not permit arbitrary relative roots.
// https://github.com/torvalds/linux/blob/master/fs/nsfs.c
func namespaceRoot(value string) bool {
	kind, suffix, ok := strings.Cut(value, ":[")
	if !ok || !strings.HasSuffix(suffix, "]") {
		return false
	}
	switch kind {
	case "mnt", "net", "uts", "ipc", "pid", "user", "cgroup", "time":
	default:
		return false
	}
	_, valid := canonicalUint(strings.TrimSuffix(suffix, "]"), 64, true)
	return valid
}

func mountBinding(m Mount) string {
	// Deliberately exclude source, credentials and every raw options string.
	wire, _ := json.Marshal([]any{m.ID, m.ParentID, m.Major, m.Minor, hex.EncodeToString([]byte(m.rawRoot)), hex.EncodeToString([]byte(m.rawPoint)), m.Filesystem, m.ReadOnly})
	h := sha256.Sum256(wire)
	return hex.EncodeToString(h[:])
}

// ParseMountInfo accepts a complete bounded mountinfo read or fails closed.
// It makes NO filesystem/path lookups and does not turn parsing into a scan
// permission. In particular it cannot hang trying to stat a hard NFS mount.
func ParseMountInfo(reader io.Reader) (Inventory, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MountInfoBytesMax+1))
	if err != nil || len(data) == 0 || len(data) > MountInfoBytesMax || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		return Inventory{}, ErrMountInventory
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), mountLineBytesMax)
	seen, points := map[string]bool{}, map[string]int{}
	mounts := []Mount{}
	for scanner.Scan() {
		left, right, ok := strings.Cut(scanner.Text(), " - ")
		// Only ASCII space is a kernel separator. strings.Fields would split
		// legitimate mount names containing Unicode whitespace such as NBSP.
		fields, filesystem := strings.Split(left, " "), strings.Split(right, " ")
		if !ok || len(fields) < 6 || len(filesystem) != 3 || len(mounts) >= MountCountMax {
			return Inventory{}, ErrMountInventory
		}
		for _, field := range append(fields, filesystem...) {
			if field == "" {
				return Inventory{}, ErrMountInventory
			}
		}
		_, idOK := canonicalUint(fields[0], 64, true)
		_, parentOK := canonicalUint(fields[1], 64, true)
		majorText, minorText, deviceOK := strings.Cut(fields[2], ":")
		major, majorOK := canonicalUint(majorText, 32, false)
		minor, minorOK := canonicalUint(minorText, 32, false)
		root, rootOK := mountUnescape(fields[3])
		point, pointOK := mountUnescape(fields[4])
		if !idOK || !parentOK || seen[fields[0]] || !deviceOK || !majorOK || !minorOK || !rootOK || !pointOK || root == "" || point == "" || root[0] != '/' && !(filesystem[0] == "nsfs" && namespaceRoot(root)) || point[0] != '/' || len(root) > 4096 || len(point) > 4096 {
			return Inventory{}, ErrMountInventory
		}
		fs := filesystem[0]
		if fs == "" || len(fs) > 64 || strings.IndexFunc(fs, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
		}) >= 0 {
			return Inventory{}, ErrMountInventory
		}
		ro, rw := 0, 0
		for _, option := range strings.Split(fields[5], ",") {
			if option == "ro" {
				ro++
			}
			if option == "rw" {
				rw++
			}
		}
		if ro+rw != 1 {
			return Inventory{}, ErrMountInventory
		}
		seen[fields[0]], points[point] = true, points[point]+1
		m := Mount{ID: fields[0], ParentID: fields[1], Major: uint32(major), Minor: uint32(minor), Root: strings.ToValidUTF8(root, "�"), Point: strings.ToValidUTF8(point, "�"), Filesystem: fs, ReadOnly: ro == 1, Class: filesystemClass(fs), Actionable: ValidHostPath(root) && ValidHostPath(point), rawRoot: root, rawPoint: point}
		m.BindingSHA = mountBinding(m)
		mounts = append(mounts, m)
	}
	if scanner.Err() != nil || len(mounts) == 0 {
		return Inventory{}, ErrMountInventory
	}
	bindings := make([]string, len(mounts))
	for n := range mounts {
		mounts[n].Stacked = points[mounts[n].rawPoint] > 1
		bindings[n] = mounts[n].BindingSHA
	}
	sort.Strings(bindings)
	wire, _ := json.Marshal(bindings)
	h := sha256.Sum256(wire)
	return Inventory{Format: 1, Mounts: mounts, BindingSHA: hex.EncodeToString(h[:]), MountListComplete: true, SnapshotConsistent: false}, nil
}
