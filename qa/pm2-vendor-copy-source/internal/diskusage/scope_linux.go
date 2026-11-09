//go:build linux

package diskusage

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const ReadBatchSize = 64

var (
	ErrUnsafePath                = errors.New("目录路径不能安全定位；未跟随链接或解释为命令")
	ErrMountChanged              = errors.New("挂载身份已变化或不能核对；请重新读取挂载清单")
	ErrMountBoundary             = errors.New("路径越过挂载点；该挂载应作为独立扫描范围")
	ErrKernelBoundaryUnavailable = errors.New("内核或隔离策略不提供所需的挂载边界验证；未降级为不安全扫描")
	ErrPathUnavailable           = errors.New("目录项已变化、不可读取或元数据不可用；不得按零占用计算")
	ErrScopeClosed               = errors.New("扫描范围已关闭")
	ErrNotLocal                  = errors.New("此挂载为内核虚拟、远程或未知文件系统；未自动探测其目录或伪造容量")
)

// ReadInventory has one fixed kernel path, no configurable alternate root and
// no filesystem probes. Mount source/super-options never enter its result.
func ReadInventory() (Inventory, error) {
	fd, err := unix.Open("/proc/self/mountinfo", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Inventory{}, ErrMountInventory
	}
	f := os.NewFile(uintptr(fd), "kernel-mountinfo")
	defer f.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return Inventory{}, ErrMountInventory
	}
	return ParseMountInfo(f)
}

type Identity struct {
	MountID      uint64
	Major, Minor uint32
	Inode        uint64
}

type Metadata struct {
	Identity      Identity
	Mode          uint16
	Bytes, Blocks uint64
	Links         uint32
}

func metadataFD(fd int, regular bool) (Metadata, error) {
	var st unix.Statx_t
	wanted := unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID
	if regular {
		wanted |= unix.STATX_SIZE | unix.STATX_BLOCKS | unix.STATX_NLINK
	}
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, wanted, &st); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return Metadata{}, ErrKernelBoundaryUnavailable
		}
		return Metadata{}, ErrPathUnavailable
	}
	if st.Mask&uint32(unix.STATX_MNT_ID) == 0 || st.Mnt_id == 0 {
		return Metadata{}, ErrKernelBoundaryUnavailable
	}
	if st.Mask&uint32(wanted) != uint32(wanted) {
		return Metadata{}, ErrPathUnavailable
	}
	return Metadata{Identity: Identity{st.Mnt_id, st.Dev_major, st.Dev_minor, st.Ino}, Mode: st.Mode, Bytes: st.Size, Blocks: st.Blocks, Links: st.Nlink}, nil
}

func resolutionError(err error) error {
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		return ErrKernelBoundaryUnavailable
	case errors.Is(err, unix.EXDEV):
		return ErrMountBoundary
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return ErrUnsafePath
	case errors.Is(err, unix.EAGAIN):
		return ErrMountChanged
	default:
		return ErrPathUnavailable
	}
}

// Scope pins a real mount directory inode. All potentially blocking local disk
// syscalls belong in the isolated scan worker, not the Core or executor mutex.
// https://man7.org/linux/man-pages/man2/openat2.2.html
// https://man7.org/linux/man-pages/man2/statx.2.html
type Scope struct {
	mu       sync.Mutex
	root     *os.File
	mount    Mount
	identity Identity
	closed   atomic.Bool
}

func (i Inventory) OpenMount(ctx context.Context, id, binding string) (*Scope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var selected *Mount
	for n := range i.Mounts {
		if i.Mounts[n].ID == id {
			if selected != nil {
				return nil, ErrMountInventory
			}
			selected = &i.Mounts[n]
		}
	}
	if selected == nil || binding == "" || binding != selected.BindingSHA || binding != mountBinding(*selected) || selected.Point != selected.rawPoint || selected.Root != selected.rawRoot || !selected.Actionable || !ValidHostPath(selected.rawPoint) || !ValidHostPath(selected.rawRoot) {
		return nil, ErrMountChanged
	}
	if !i.LocalLookup(selected.ID) {
		return nil, ErrNotLocal
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPathUnavailable
	}
	defer unix.Close(root)
	relative := strings.TrimPrefix(selected.rawPoint, "/")
	if relative == "" {
		relative = "."
	}
	fd, err := unix.Openat2(root, relative, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, resolutionError(err)
	}
	f := os.NewFile(uintptr(fd), "host-mount-directory")
	metadata, err := metadataFD(fd, false)
	want, idOK := canonicalUint(selected.ID, 64, true)
	if err != nil || !idOK || metadata.Mode&unix.S_IFMT != unix.S_IFDIR || metadata.Identity.MountID != want || metadata.Identity.Major != selected.Major || metadata.Identity.Minor != selected.Minor {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrMountChanged
	}
	if err = ctx.Err(); err != nil {
		f.Close()
		return nil, err
	}
	return &Scope{root: f, mount: *selected, identity: metadata.Identity}, nil
}

func (s *Scope) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Swap(true) {
		return nil
	}
	return s.root.Close()
}
func (s *Scope) Identity() Identity { return s.identity }

func validRelativeDirectory(value string) bool {
	if value == "" || value == "." {
		return true
	}
	return !strings.HasPrefix(value, "/") && ValidHostPath("/"+value) && path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../")
}

type Directory struct {
	mu       sync.Mutex
	file     *os.File
	scope    *Scope
	identity Identity
	closed   bool
}

func (s *Scope) checkIdentity(m Metadata) bool {
	return m.Identity.MountID == s.identity.MountID && m.Identity.Major == s.identity.Major && m.Identity.Minor == s.identity.Minor
}

func (s *Scope) openDirectory(ctx context.Context, parent int, relative string, expected *Identity) (*Directory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(parent, relative, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, resolutionError(err)
	}
	f := os.NewFile(uintptr(fd), "host-scan-directory")
	m, err := metadataFD(fd, false)
	if err != nil || !s.checkIdentity(m) || m.Mode&unix.S_IFMT != unix.S_IFDIR || expected != nil && m.Identity != *expected {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrMountChanged
	}
	if err = ctx.Err(); err != nil {
		f.Close()
		return nil, err
	}
	if s.closed.Load() {
		f.Close()
		return nil, ErrScopeClosed
	}
	return &Directory{file: f, scope: s, identity: m.Identity}, nil
}

func (s *Scope) OpenDirectory(ctx context.Context, relative string) (*Directory, error) {
	if !validRelativeDirectory(relative) {
		return nil, ErrUnsafePath
	}
	if relative == "" {
		relative = "."
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, ErrScopeClosed
	}
	return s.openDirectory(ctx, int(s.root.Fd()), relative, nil)
}

func (d *Directory) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.file.Close()
}

type Entry struct {
	// Name is native bytes. A false Actionable name must be counted but must
	// never become a GUI path action after JSON replaces invalid UTF-8.
	Name       string
	Actionable bool
	Metadata   Metadata
	Error      error
	rawName    string
}

func singleName(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsAny(value, "/\x00")
}

func (d *Directory) OpenChild(ctx context.Context, entry Entry) (*Directory, error) {
	if entry.Error != nil || entry.Metadata.Mode&unix.S_IFMT != unix.S_IFDIR || entry.Name != entry.rawName || !singleName(entry.rawName) {
		return nil, ErrUnsafePath
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.scope.closed.Load() {
		return nil, ErrScopeClosed
	}
	return d.scope.openDirectory(ctx, int(d.file.Fd()), entry.rawName, &entry.Metadata.Identity)
}

// Open each name as O_PATH, never as file content. Kernel NO_XDEV is checked
// before stat so even a same-device bind mount or hard NFS child isn't followed.
// FIFO/device/symlink handles have no data-channel or driver-open side effects.
func (d *Directory) ReadBatch(ctx context.Context) ([]Entry, error) {
	return d.ReadBatchLimited(ctx, ReadBatchSize)
}

// Limited batches let a worker's total metadata-entry budget remain exact,
// including already-read parent batches while descending into children.
func (d *Directory) ReadBatchLimited(ctx context.Context, limit int) ([]Entry, error) {
	if limit < 1 || limit > ReadBatchSize {
		return nil, ErrUnsafePath
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.scope.closed.Load() {
		return nil, ErrScopeClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// ReadDir constructs DirEntry values and can lstat a DT_UNKNOWN name.
	// Readdirnames does not resolve children before our NO_XDEV check.
	names, readErr := d.file.Readdirnames(limit)
	entries := make([]Entry, 0, len(names))
	for _, raw := range names {
		if err := ctx.Err(); err != nil {
			return entries, err
		}
		e := Entry{Name: raw, rawName: raw, Actionable: utf8.ValidString(raw) && ValidHostPath("/"+raw)}
		if !singleName(raw) {
			e.Error = ErrUnsafePath
			entries = append(entries, e)
			continue
		}
		fd, err := unix.Openat2(int(d.file.Fd()), raw, &unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			e.Error = resolutionError(err)
			entries = append(entries, e)
			continue
		}
		m, statErr := metadataFD(fd, true)
		unix.Close(fd)
		if statErr != nil {
			e.Error = statErr
		} else if !d.scope.checkIdentity(m) {
			e.Error = ErrMountChanged
		} else {
			e.Metadata = m
		}
		entries = append(entries, e)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return entries, ErrPathUnavailable
	}
	return entries, readErr
}

func (d *Directory) Metadata(ctx context.Context) (Metadata, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.scope.closed.Load() {
		return Metadata{}, ErrScopeClosed
	}
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	m, err := metadataFD(int(d.file.Fd()), true)
	if err != nil {
		return Metadata{}, err
	}
	if m.Identity != d.identity || !d.scope.checkIdentity(m) || m.Mode&unix.S_IFMT != unix.S_IFDIR {
		return Metadata{}, ErrMountChanged
	}
	return m, nil
}

// MetadataIdentityKey is private indexing material, not a capacity identity or
// an assertion about exclusive physical extents shared by snapshots/reflinks.
func MetadataIdentityKey(m Metadata) string {
	return strconv.FormatUint(uint64(m.Identity.Major), 10) + ":" + strconv.FormatUint(uint64(m.Identity.Minor), 10) + ":" + strconv.FormatUint(m.Identity.MountID, 10) + ":" + strconv.FormatUint(m.Identity.Inode, 10)
}
