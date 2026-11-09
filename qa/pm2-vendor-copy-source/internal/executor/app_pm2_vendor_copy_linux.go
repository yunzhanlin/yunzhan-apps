//go:build linux

package executor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Package archives can retain their publisher's numeric UID. Never chown an
// extracted shared runtime in place: an older writable descriptor survives
// chown. Build privately, copy into new Root-owned inodes, and publish by an
// atomic directory operation. The previous directory stays below a private
// Root parent, including after errors. These helpers accept no HTTP input.
const pm2VendorIndexName = ".root-owned-pm2-vendor.json"
const pm2VendorMaxEntries = 32768
const pm2VendorMaxFile = int64(256 << 20)
const pm2VendorMaxBytes = int64(1 << 30)

type pm2VendorEntry struct {
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

type pm2VendorWorkspace struct {
	path   string
	parent *os.File
	dir    *os.File
}

func pm2VendorComponent(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && !strings.ContainsAny(name, "/\x00")
}

func pm2VendorStat(file *os.File) (unix.Stat_t, error) {
	var value unix.Stat_t
	err := unix.Fstat(int(file.Fd()), &value)
	return value, err
}

func pm2VendorSame(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func pm2VendorAt(parent *os.File, name string) (unix.Stat_t, error) {
	var value unix.Stat_t
	if !pm2VendorComponent(name) {
		return value, errors.New("invalid PM2 runtime entry")
	}
	err := unix.Fstatat(int(parent.Fd()), name, &value, unix.AT_SYMLINK_NOFOLLOW)
	return value, err
}

func pm2VendorOpenDirectory(parent *os.File, name string) (*os.File, error) {
	if !pm2VendorComponent(name) {
		return nil, errors.New("invalid PM2 directory entry")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func pm2VendorOpenProtectedParent(parentPath string) (*os.File, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(parentPath) || filepath.Clean(parentPath) != parentPath {
		return nil, errors.New("PM2 runtime publication requires a fixed ordinary Root parent")
	}
	// Walk from / through held no-follow descriptors, including a separately
	// mounted /opt. Never resolve an administrator-supplied symlink here.
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(fd), "/")
	for _, name := range strings.Split(strings.TrimPrefix(parentPath, "/"), "/") {
		if name == "" {
			continue
		}
		next, openErr := pm2VendorOpenDirectory(parent, name)
		parent.Close()
		if openErr != nil {
			return nil, openErr
		}
		parent = next
		st, statErr := pm2VendorStat(parent)
		if statErr != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
			parent.Close()
			return nil, errors.New("PM2 runtime parent is not an ordinary protected Root directory")
		}
	}
	return parent, nil
}

func newPM2VendorWorkspace(parentPath string) (*pm2VendorWorkspace, error) {
	parent, err := pm2VendorOpenProtectedParent(parentPath)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		parent.Close()
		return nil, err
	}
	name := ".pm2-vendor-" + hex.EncodeToString(nonce[:])
	if err = unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		parent.Close()
		return nil, err
	}
	dir, err := pm2VendorOpenDirectory(parent, name)
	if err != nil {
		parent.Close()
		return nil, err // Leave the original newly created directory for review.
	}
	if err = unix.Fchmod(int(dir.Fd()), 0700); err == nil {
		err = unix.Fchown(int(dir.Fd()), 0, 0)
	}
	if err == nil {
		err = parent.Sync()
	}
	if err != nil {
		dir.Close()
		parent.Close()
		return nil, err
	}
	return &pm2VendorWorkspace{path: filepath.Join(parentPath, name), parent: parent, dir: dir}, nil
}

func (w *pm2VendorWorkspace) close() {
	if w != nil {
		w.dir.Close()
		w.parent.Close()
	}
}

func (w *pm2VendorWorkspace) private() error {
	st, err := pm2VendorStat(w.dir)
	if err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 {
		return errors.New("PM2 original runtime workspace is no longer private")
	}
	visible, err := pm2VendorAt(w.parent, filepath.Base(w.path))
	if err != nil || visible.Dev != st.Dev || visible.Ino != st.Ino {
		return errors.New("PM2 private runtime workspace identity changed")
	}
	return nil
}

func (w *pm2VendorWorkspace) writeRecord(name string, value any, mode uint32) error {
	if err := w.private(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(raw) > 8<<20 {
		return errors.New("PM2 runtime evidence exceeds the fixed record bound")
	}
	return pm2VendorWriteNew(w.dir, name, append(raw, '\n'), mode)
}

func pm2VendorWriteNew(parent *os.File, name string, raw []byte, mode uint32) error {
	if !pm2VendorComponent(name) {
		return errors.New("invalid PM2 runtime record name")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err = unix.Fchown(fd, 0, 0); err == nil {
		err = unix.Fchmod(fd, mode)
	}
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = parent.Sync()
	}
	return err
}

func pm2VendorCheckLinks(entries map[string]pm2VendorEntry) error {
	for name, entry := range entries {
		if entry.Kind != "link" {
			continue
		}
		if entry.Target == "" || path.IsAbs(entry.Target) || strings.ContainsRune(entry.Target, 0) || len(entry.Target) > 4096 {
			return errors.New("PM2 runtime link is not a bounded relative dependency link")
		}
		resolved := path.Clean(path.Join(path.Dir(name), entry.Target))
		seen := map[string]bool{name: true}
		for depth := 0; ; depth++ {
			if depth >= 16 || resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") || seen[resolved] {
				return errors.New("PM2 runtime link escapes or loops")
			}
			seen[resolved] = true
			target, ok := entries[resolved]
			if !ok {
				return errors.New("PM2 runtime link target is missing")
			}
			// An intermediate link must not turn a lexical internal path into
			// a different namespace. npm's executable links target real files.
			for ancestor := path.Dir(resolved); ancestor != "."; ancestor = path.Dir(ancestor) {
				if entries[ancestor].Kind != "directory" {
					return errors.New("PM2 runtime link crosses a non-directory ancestor")
				}
			}
			if target.Kind == "file" {
				break
			}
			if target.Kind != "link" || path.IsAbs(target.Target) {
				return errors.New("PM2 runtime executable link is not an ordinary internal file")
			}
			resolved = path.Clean(path.Join(path.Dir(resolved), target.Target))
		}
	}
	return nil
}

type pm2VendorContextReader struct {
	ctx context.Context
	src io.Reader
}

func (r pm2VendorContextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.src.Read(b)
}

func (w *pm2VendorWorkspace) copyIndependent(ctx context.Context, sourceName, targetName string) (map[string]pm2VendorEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := w.private(); err != nil {
		return nil, err
	}
	if !pm2VendorComponent(sourceName) || !pm2VendorComponent(targetName) || sourceName == targetName {
		return nil, errors.New("invalid PM2 private copy names")
	}
	source, err := pm2VendorOpenDirectory(w.dir, sourceName)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	initial, err := pm2VendorStat(source)
	if err != nil || initial.Uid != 0 || initial.Mode&07777 != 0700 {
		return nil, errors.New("PM2 extracted input must remain below its original private Root directory")
	}
	if err = unix.Mkdirat(int(w.dir.Fd()), targetName, 0700); err != nil {
		return nil, err
	}
	target, err := pm2VendorOpenDirectory(w.dir, targetName)
	if err != nil {
		return nil, err
	}
	defer target.Close()
	entries := map[string]pm2VendorEntry{".": {Kind: "directory", Mode: 0755}}
	var total int64
	var copyDir func(*os.File, *os.File, string, int) error
	copyDir = func(from, to *os.File, prefix string, depth int) error {
		if depth > 64 || len(prefix) > 4096 {
			return errors.New("PM2 runtime directory bound exceeded")
		}
		before, e := pm2VendorStat(from)
		if e != nil {
			return e
		}
		children, e := from.ReadDir(-1)
		if e != nil {
			return e
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			if e = ctx.Err(); e != nil {
				return e
			}
			name := child.Name()
			if prefix == "" && name == ".cache" {
				continue // npm download cache is retained privately, never published.
			}
			if !pm2VendorComponent(name) || prefix == "" && name == pm2VendorIndexName || len(entries) >= pm2VendorMaxEntries {
				return errors.New("PM2 runtime entry name, reserved index or count refused")
			}
			rel := path.Join(prefix, name)
			st, e := pm2VendorAt(from, name)
			if e != nil {
				return e
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				in, e := pm2VendorOpenDirectory(from, name)
				if e != nil {
					return e
				}
				e = unix.Mkdirat(int(to.Fd()), name, 0700)
				var out *os.File
				if e == nil {
					out, e = pm2VendorOpenDirectory(to, name)
				}
				if e == nil {
					entries[rel] = pm2VendorEntry{Kind: "directory", Mode: 0755}
					e = copyDir(in, out, rel, depth+1)
				}
				if out != nil {
					out.Close()
				}
				in.Close()
				if e != nil {
					return e
				}
			case unix.S_IFREG:
				if st.Nlink != 1 || st.Size < 0 || st.Size > pm2VendorMaxFile || st.Size > pm2VendorMaxBytes-total {
					return errors.New("PM2 runtime ordinary-file size, hard-link or total bound refused")
				}
				total += st.Size
				fd, e := unix.Openat(int(from.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if e != nil {
					return e
				}
				in := os.NewFile(uintptr(fd), rel)
				opened, e := pm2VendorStat(in)
				if e != nil || !pm2VendorSame(st, opened) {
					in.Close()
					return errors.New("PM2 runtime source file identity changed before copy")
				}
				outFD, e := unix.Openat(int(to.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
				if e != nil {
					in.Close()
					return e
				}
				out := os.NewFile(uintptr(outFD), rel)
				hash := sha256.New()
				n, e := io.CopyBuffer(io.MultiWriter(out, hash), io.LimitReader(pm2VendorContextReader{ctx, in}, st.Size+1), make([]byte, 64<<10))
				mode := uint32(0644)
				if st.Mode&0111 != 0 {
					mode = 0755
				}
				if e == nil && n == st.Size {
					e = unix.Fchown(outFD, 0, 0)
					if e == nil {
						e = unix.Fchmod(outFD, mode)
					}
					if e == nil {
						e = out.Sync()
					}
				} else if e == nil {
					e = errors.New("PM2 runtime source changed length during copy")
				}
				after, statErr := pm2VendorStat(in)
				visible, pathErr := pm2VendorAt(from, name)
				in.Close()
				out.Close()
				if e != nil {
					return e
				}
				if statErr != nil || pathErr != nil || !pm2VendorSame(st, after) || !pm2VendorSame(st, visible) {
					return errors.New("PM2 runtime source changed while copying; original inputs retained")
				}
				entries[rel] = pm2VendorEntry{Kind: "file", Mode: mode, Bytes: n, SHA256: hex.EncodeToString(hash.Sum(nil))}
			case unix.S_IFLNK:
				buf := make([]byte, 4097)
				n, e := unix.Readlinkat(int(from.Fd()), name, buf)
				if e != nil || n == len(buf) || st.Nlink != 1 {
					return errors.New("PM2 runtime source link is not bounded")
				}
				if e = unix.Symlinkat(string(buf[:n]), int(to.Fd()), name); e != nil {
					return e
				}
				if e = unix.Fchownat(int(to.Fd()), name, 0, 0, unix.AT_SYMLINK_NOFOLLOW); e != nil {
					return e
				}
				visible, e := pm2VendorAt(from, name)
				if e != nil || !pm2VendorSame(st, visible) {
					return errors.New("PM2 runtime source link identity changed")
				}
				entries[rel] = pm2VendorEntry{Kind: "link", Target: string(buf[:n])}
			default:
				return errors.New("PM2 runtime refused a nonordinary dependency entry")
			}
		}
		after, e := pm2VendorStat(from)
		if e != nil || !pm2VendorSame(before, after) {
			return errors.New("PM2 runtime source directory changed")
		}
		if e = unix.Fchown(int(to.Fd()), 0, 0); e == nil {
			e = unix.Fchmod(int(to.Fd()), 0755)
		}
		if e == nil {
			e = to.Sync()
		}
		return e
	}
	if err = copyDir(source, target, "", 0); err != nil {
		return nil, err
	}
	visible, err := pm2VendorAt(w.dir, sourceName)
	if err != nil || !pm2VendorSame(initial, visible) {
		return nil, errors.New("PM2 private extracted source root changed")
	}
	if err = pm2VendorCheckLinks(entries); err != nil {
		return nil, err
	}
	if err = w.dir.Sync(); err != nil {
		return nil, err
	}
	return entries, nil
}

// verifyIndependent uses held no-follow descriptors. It is also suitable for
// read-only readiness: metadata-only checks never execute an npm/PM2 script.
func (w *pm2VendorWorkspace) verifyIndependent(ctx context.Context, name string, expected map[string]pm2VendorEntry, content bool) error {
	if err := w.private(); err != nil {
		return err
	}
	root, err := pm2VendorOpenDirectory(w.dir, name)
	if err != nil {
		return err
	}
	defer root.Close()
	seen := make(map[string]pm2VendorEntry)
	var walk func(*os.File, string, int) error
	walk = func(dir *os.File, prefix string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		st, err := pm2VendorStat(dir)
		if err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0755 || depth > 64 {
			return errors.New("PM2 copied runtime directory ownership, mode or depth invalid")
		}
		key := prefix
		if key == "" {
			key = "."
		}
		seen[key] = pm2VendorEntry{Kind: "directory", Mode: 0755}
		children, err := dir.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := ctx.Err(); err != nil {
				return err
			}
			rel := path.Join(prefix, child.Name())
			entry, ok := expected[rel]
			if !ok || len(seen) >= pm2VendorMaxEntries {
				return errors.New("PM2 copied runtime has an unknown or excessive entry")
			}
			st, err := pm2VendorAt(dir, child.Name())
			if err != nil || st.Uid != 0 || st.Gid != 0 {
				return errors.New("PM2 copied runtime entry is not owned by Root")
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if entry.Kind != "directory" {
					return errors.New("PM2 copied runtime type changed")
				}
				next, err := pm2VendorOpenDirectory(dir, child.Name())
				if err != nil {
					return err
				}
				err = walk(next, rel, depth+1)
				next.Close()
				if err != nil {
					return err
				}
			case unix.S_IFREG:
				if entry.Kind != "file" || st.Nlink != 1 || st.Size != entry.Bytes || st.Mode&07777 != entry.Mode {
					return errors.New("PM2 copied runtime ordinary file metadata changed")
				}
				if content {
					fd, err := unix.Openat(int(dir.Fd()), child.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
					if err != nil {
						return err
					}
					f := os.NewFile(uintptr(fd), rel)
					opened, openErr := pm2VendorStat(f)
					hash := sha256.New()
					n, readErr := io.Copy(hash, io.LimitReader(pm2VendorContextReader{ctx, f}, st.Size+1))
					last, statErr := pm2VendorStat(f)
					visible, pathErr := pm2VendorAt(dir, child.Name())
					f.Close()
					if openErr != nil || readErr != nil || statErr != nil || pathErr != nil || !pm2VendorSame(st, opened) || !pm2VendorSame(st, last) || !pm2VendorSame(st, visible) || n != st.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
						return errors.New("PM2 copied runtime file contents or identity changed")
					}
				}
				seen[rel] = entry
			case unix.S_IFLNK:
				buf := make([]byte, 4097)
				n, err := unix.Readlinkat(int(dir.Fd()), child.Name(), buf)
				if err != nil || n == len(buf) || entry.Kind != "link" || st.Nlink != 1 || string(buf[:n]) != entry.Target {
					return errors.New("PM2 copied runtime dependency link changed")
				}
				seen[rel] = entry
			default:
				return errors.New("PM2 copied runtime contains a nonordinary entry")
			}
		}
		return nil
	}
	if err = walk(root, "", 0); err != nil {
		return err
	}
	if !reflect.DeepEqual(seen, expected) {
		return errors.New("PM2 copied runtime inventory changed")
	}
	return pm2VendorCheckLinks(seen)
}

type pm2VendorPublication struct {
	Published bool   `json:"published"`
	Retained  bool   `json:"original_directory_retained"`
	Workspace string `json:"private_evidence_directory"`
}

func (w *pm2VendorWorkspace) publishIndependent(ctx context.Context, candidate string, entries map[string]pm2VendorEntry) (pm2VendorPublication, error) {
	result := pm2VendorPublication{Workspace: w.path}
	if candidate != "candidate" {
		return result, errors.New("PM2 publication candidate name is fixed")
	}
	if err := w.verifyIndependent(ctx, candidate, entries, true); err != nil {
		return result, err
	}
	newIdentity, err := pm2VendorAt(w.dir, candidate)
	if err != nil {
		return result, err
	}
	old, oldErr := pm2VendorAt(w.parent, "pm2")
	if oldErr != nil && !errors.Is(oldErr, unix.ENOENT) {
		return result, oldErr
	}
	if oldErr == nil && (old.Mode&unix.S_IFMT != unix.S_IFDIR || old.Uid != 0 || old.Mode&0022 != 0 || old.Dev != newIdentity.Dev) {
		return result, errors.New("original PM2 runtime directory identity is unverified; retained without replacement")
	}
	if err = w.writeRecord("original-publication-prepared.json", map[string]any{"format": 1, "new_identity": newIdentity, "original_present": oldErr == nil, "original_identity": old, "entries": entries, "maximum_atomic_publications": 1}, 0600); err != nil {
		return result, err
	}
	flag := uint(unix.RENAME_NOREPLACE)
	if oldErr == nil {
		flag = unix.RENAME_EXCHANGE
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = unix.Renameat2(int(w.dir.Fd()), candidate, int(w.parent.Fd()), "pm2", flag); err != nil {
		return result, fmt.Errorf("PM2 requires an atomic same-filesystem publication; originals retained: %w", err)
	}
	result.Published = true
	result.Retained = oldErr == nil
	// No pathname fallback, rollback overwrite, recursive chown or deletion.
	// An error after exchange is a published-but-unconfirmed outcome, retained
	// in the result; callers must observe it rather than replay the exchange.
	if err = w.parent.Sync(); err == nil {
		err = w.dir.Sync()
	}
	if err != nil {
		return result, err
	}
	current, err := pm2VendorAt(w.parent, "pm2")
	if err != nil || current.Dev != newIdentity.Dev || current.Ino != newIdentity.Ino {
		return result, errors.New("PM2 new public runtime identity cannot be confirmed; original private evidence retained")
	}
	if result.Retained {
		retained, err := pm2VendorAt(w.dir, candidate)
		if err != nil || retained.Dev != old.Dev || retained.Ino != old.Ino || retained.Uid != old.Uid || retained.Gid != old.Gid || retained.Mode != old.Mode {
			return result, errors.New("PM2 original retained directory identity cannot be confirmed")
		}
	}
	if err = w.writeRecord("original-publication-completed.json", result, 0600); err != nil {
		return result, err
	}
	return result, nil
}
