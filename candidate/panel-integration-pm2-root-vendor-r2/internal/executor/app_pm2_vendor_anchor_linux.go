//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

// The private seal records the new inodes and ctimes, not just current UID
// bits. Temporarily chowning an old inode back to Root cannot conceal an
// unprivileged writer which already opened it while it was writable.
type pm2VendorStamp struct {
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	Mode      uint32 `json:"mode"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Links     uint64 `json:"links"`
	Bytes     int64  `json:"bytes"`
	CTimeSec  int64  `json:"ctime_sec"`
	CTimeNsec int64  `json:"ctime_nsec"`
}

func pm2VendorStampOf(st unix.Stat_t) pm2VendorStamp {
	value := pm2VendorStamp{Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, UID: st.Uid, GID: st.Gid, Links: uint64(st.Nlink), Bytes: st.Size, CTimeSec: st.Ctim.Sec, CTimeNsec: st.Ctim.Nsec}
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		// Directory rename changes the root ctime and adding the authoritative
		// pointer can change its allocated directory size. Every child name,
		// inode and immutable file ctime is independently bound below.
		value.Bytes, value.CTimeSec, value.CTimeNsec = 0, 0, 0
	}
	return value
}

type pm2VendorAnchor struct {
	Format        int                       `json:"format"`
	Upstream      string                    `json:"upstream"`
	PackageSHA256 string                    `json:"package_sha256"`
	LockSHA256    string                    `json:"lock_sha256"`
	Entries       map[string]pm2VendorEntry `json:"entries"`
	Identities    map[string]pm2VendorStamp `json:"identities"`
}

type pm2VendorPointer struct {
	Format       int    `json:"format"`
	Workspace    string `json:"workspace"`
	AnchorSHA256 string `json:"anchor_sha256"`
}

func pm2VendorHash(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func pm2VendorBoundInputs(entries map[string]pm2VendorEntry) error {
	if len(entries) < 5 || len(entries) > pm2VendorMaxEntries {
		return errors.New("PM2 Root vendor input inventory is missing or excessive")
	}
	var total int64
	for name, entry := range entries {
		if len(name) > 4096 || path.Clean(name) != name || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return errors.New("PM2 Root vendor private input path invalid")
		}
		first := strings.Split(name, "/")[0]
		if first != "." && first != "package.json" && first != "package-lock.json" && first != "node_modules" && first != "node" {
			return errors.New("PM2 Root vendor has an unknown top-level input")
		}
		if entry.Kind == "file" {
			decoded, err := hex.DecodeString(entry.SHA256)
			if err != nil || len(decoded) != 32 || len(entry.SHA256) != 64 || entry.SHA256 != strings.ToLower(entry.SHA256) || entry.Bytes < 0 || entry.Bytes > pm2VendorMaxFile || entry.Bytes > pm2VendorMaxBytes-total {
				return errors.New("PM2 Root vendor private input digest or byte bound invalid")
			}
			total += entry.Bytes
		}
	}
	for name, raw := range map[string][]byte{"package.json": pm2Package, "package-lock.json": pm2Lock} {
		if entries[name] != (pm2VendorEntry{Kind: "file", Mode: 0644, Bytes: int64(len(raw)), SHA256: pm2VendorHash(raw)}) {
			return errors.New("PM2 Root vendor is not bound to the exact compiled package and lock")
		}
	}
	upstream := entries["node_modules/pm2/package.json"]
	if upstream.Kind != "file" || upstream.Mode != 0644 || upstream.Bytes < 1 || upstream.Bytes > 1<<20 {
		return errors.New("PM2 Root vendor upstream package record is missing or invalid")
	}
	return nil
}

func pm2VendorCollectIdentities(ctx context.Context, root *os.File, expected map[string]pm2VendorEntry, withPointer bool) (map[string]pm2VendorStamp, error) {
	if len(expected) < 1 || len(expected) > pm2VendorMaxEntries || expected["."].Kind != "directory" {
		return nil, errors.New("PM2 Root vendor index is missing or excessive")
	}
	identities := make(map[string]pm2VendorStamp)
	var visit func(*os.File, string, int) error
	visit = func(dir *os.File, prefix string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		st, err := pm2VendorStat(dir)
		if err != nil || depth > 64 || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0755 {
			return errors.New("PM2 Root vendor directory identity or permissions invalid")
		}
		key := prefix
		if key == "" {
			key = "."
		}
		if expected[key] != (pm2VendorEntry{Kind: "directory", Mode: 0755}) {
			return errors.New("PM2 Root vendor directory does not match its private seal")
		}
		identities[key] = pm2VendorStampOf(st)
		children, err := dir.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := child.Name()
			if prefix == "" && name == pm2VendorIndexName && withPointer {
				continue // Independently bound to its own private inode/ctime record.
			}
			rel := path.Join(prefix, name)
			entry, ok := expected[rel]
			if !ok || len(identities) >= pm2VendorMaxEntries || len(rel) > 4096 {
				return errors.New("PM2 Root vendor has an unsealed or excessive entry")
			}
			st, err := pm2VendorAt(dir, name)
			if err != nil || st.Uid != 0 || st.Gid != 0 {
				return errors.New("PM2 Root vendor entry is not owned by Root")
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if entry.Kind != "directory" {
					return errors.New("PM2 Root vendor entry type changed")
				}
				next, err := pm2VendorOpenDirectory(dir, name)
				if err != nil {
					return err
				}
				err = visit(next, rel, depth+1)
				next.Close()
				if err != nil {
					return err
				}
			case unix.S_IFREG:
				if entry.Kind != "file" || st.Nlink != 1 || st.Size != entry.Bytes || st.Size < 0 || st.Size > pm2VendorMaxFile || entry.Mode != 0644 && entry.Mode != 0755 || st.Mode&07777 != entry.Mode {
					return errors.New("PM2 Root vendor file metadata differs from its private seal")
				}
				identities[rel] = pm2VendorStampOf(st)
			case unix.S_IFLNK:
				buf := make([]byte, 4097)
				n, err := unix.Readlinkat(int(dir.Fd()), name, buf)
				if err != nil || n == len(buf) || entry.Kind != "link" || st.Nlink != 1 || string(buf[:n]) != entry.Target {
					return errors.New("PM2 Root vendor dependency link changed")
				}
				identities[rel] = pm2VendorStampOf(st)
			default:
				return errors.New("PM2 Root vendor contains a nonordinary entry")
			}
		}
		return nil
	}
	if err := visit(root, "", 0); err != nil {
		return nil, err
	}
	if len(identities) != len(expected) {
		return nil, errors.New("PM2 Root vendor sealed entry is missing")
	}
	if err := pm2VendorCheckLinks(expected); err != nil {
		return nil, err
	}
	return identities, nil
}

func pm2VendorReadRecord(parent *os.File, name string, limit int64, mode uint32) ([]byte, pm2VendorStamp, error) {
	var empty pm2VendorStamp
	before, err := pm2VendorAt(parent, name)
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 || before.Mode&07777 != mode || before.Size < 0 || before.Size > limit {
		return nil, empty, errors.New("PM2 Root vendor authority record identity, type, ownership or size invalid")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, empty, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	opened, err := pm2VendorStat(f)
	if err != nil || !pm2VendorSame(before, opened) {
		return nil, empty, errors.New("PM2 Root vendor authority record changed before read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) != before.Size {
		return nil, empty, errors.New("PM2 Root vendor authority record length changed")
	}
	after, statErr := pm2VendorStat(f)
	visible, pathErr := pm2VendorAt(parent, name)
	if statErr != nil || pathErr != nil || !pm2VendorSame(before, after) || !pm2VendorSame(before, visible) {
		return nil, empty, errors.New("PM2 Root vendor authority record changed during read")
	}
	return raw, pm2VendorStampOf(before), nil
}

func pm2VendorDecodeRecord(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("PM2 Root vendor authority record has trailing data")
	}
	return nil
}

func (w *pm2VendorWorkspace) sealCandidate(ctx context.Context, candidate string, entries map[string]pm2VendorEntry) (map[string]pm2VendorEntry, error) {
	if candidate != "candidate" {
		return nil, errors.New("PM2 Root vendor candidate name is fixed")
	}
	if err := pm2VendorBoundInputs(entries); err != nil {
		return nil, err
	}
	if err := w.verifyIndependent(ctx, candidate, entries, true); err != nil {
		return nil, err
	}
	root, err := pm2VendorOpenDirectory(w.dir, candidate)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	modules, err := pm2VendorOpenDirectory(root, "node_modules")
	if err != nil {
		return nil, err
	}
	upstream, err := pm2VendorOpenDirectory(modules, "pm2")
	modules.Close()
	if err != nil {
		return nil, err
	}
	packageRaw, _, err := pm2VendorReadRecord(upstream, "package.json", 1<<20, 0644)
	upstream.Close()
	if err != nil {
		return nil, err
	}
	var packageVersion struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(packageRaw, &packageVersion) != nil || packageVersion.Name != "pm2" || packageVersion.Version != "7.0.4" {
		return nil, errors.New("PM2 Root vendor actual upstream package identity cannot be verified")
	}
	identities, err := pm2VendorCollectIdentities(ctx, root, entries, false)
	if err != nil {
		return nil, err
	}
	anchor := pm2VendorAnchor{Format: 1, Upstream: "7.0.4", PackageSHA256: pm2VendorHash(pm2Package), LockSHA256: pm2VendorHash(pm2Lock), Entries: entries, Identities: identities}
	if err = w.writeRecord("vendor-anchor.json", anchor, 0600); err != nil {
		return nil, err
	}
	anchorRaw, _, err := pm2VendorReadRecord(w.dir, "vendor-anchor.json", 8<<20, 0600)
	if err != nil {
		return nil, err
	}
	pointer := pm2VendorPointer{Format: 1, Workspace: filepath.Base(w.path), AnchorSHA256: pm2VendorHash(anchorRaw)}
	raw, err := json.Marshal(pointer)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if err = pm2VendorWriteNew(root, pm2VendorIndexName, raw, 0644); err != nil {
		return nil, err
	}
	_, identity, err := pm2VendorReadRecord(root, pm2VendorIndexName, 4096, 0644)
	if err != nil {
		return nil, err
	}
	if err = w.writeRecord("original-pointer-identity.json", identity, 0600); err != nil {
		return nil, err
	}
	sealed := make(map[string]pm2VendorEntry, len(entries)+1)
	for name, entry := range entries {
		sealed[name] = entry
	}
	sealed[pm2VendorIndexName] = pm2VendorEntry{Kind: "file", Mode: 0644, Bytes: int64(len(raw)), SHA256: pm2VendorHash(raw)}
	if err = w.verifyIndependent(ctx, candidate, sealed, true); err != nil {
		return nil, err
	}
	return sealed, nil
}

// This is a side-effect-free predicate. It never installs, repairs, chowns,
// makes a new workspace, executes PM2/JavaScript, or follows an original link.
func pm2VendorSealedReadyAt(ctx context.Context, parentPath string) error {
	parent, err := pm2VendorOpenProtectedParent(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	root, err := pm2VendorOpenDirectory(parent, "pm2")
	if err != nil {
		return err
	}
	defer root.Close()
	raw, pointerIdentity, err := pm2VendorReadRecord(root, pm2VendorIndexName, 4096, 0644)
	if err != nil {
		return err
	}
	var pointer pm2VendorPointer
	if err = pm2VendorDecodeRecord(raw, &pointer); err != nil {
		return err
	}
	nonce := strings.TrimPrefix(pointer.Workspace, ".pm2-vendor-")
	decoded, nonceErr := hex.DecodeString(nonce)
	if pointer.Format != 1 || nonceErr != nil || len(decoded) != 16 || len(nonce) != 32 || pointer.Workspace != ".pm2-vendor-"+strings.ToLower(nonce) || len(pointer.AnchorSHA256) != 64 || pointer.AnchorSHA256 != strings.ToLower(pointer.AnchorSHA256) {
		return errors.New("PM2 Root vendor pointer is not a fixed publication authority")
	}
	private, err := pm2VendorOpenDirectory(parent, pointer.Workspace)
	if err != nil {
		return err
	}
	defer private.Close()
	st, err := pm2VendorStat(private)
	if err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0700 {
		return errors.New("PM2 original Root vendor authority directory is not private")
	}
	completedRaw, _, err := pm2VendorReadRecord(private, "original-publication-completed.json", 8192, 0600)
	var completed pm2VendorPublication
	if err != nil || pm2VendorDecodeRecord(completedRaw, &completed) != nil || !completed.Published || completed.Workspace != filepath.Join(parentPath, pointer.Workspace) {
		return errors.New("PM2 original Root publication outcome is unconfirmed; retained evidence must be inspected")
	}
	anchorRaw, _, err := pm2VendorReadRecord(private, "vendor-anchor.json", 8<<20, 0600)
	if err != nil || pm2VendorHash(anchorRaw) != pointer.AnchorSHA256 {
		return errors.New("PM2 original Root vendor private anchor hash cannot be verified")
	}
	identityRaw, _, err := pm2VendorReadRecord(private, "original-pointer-identity.json", 4096, 0600)
	if err != nil {
		return err
	}
	var savedPointer pm2VendorStamp
	if err = pm2VendorDecodeRecord(identityRaw, &savedPointer); err != nil || savedPointer != pointerIdentity {
		return errors.New("PM2 original public vendor pointer inode or ctime changed")
	}
	var anchor pm2VendorAnchor
	if err = pm2VendorDecodeRecord(anchorRaw, &anchor); err != nil {
		return err
	}
	if anchor.Format != 1 || anchor.Upstream != "7.0.4" || anchor.PackageSHA256 != pm2VendorHash(pm2Package) || anchor.LockSHA256 != pm2VendorHash(pm2Lock) || len(anchor.Entries) != len(anchor.Identities) {
		return errors.New("PM2 private vendor seal is not bound to the exact compiled dependency inputs")
	}
	if err := pm2VendorBoundInputs(anchor.Entries); err != nil {
		return err
	}
	identities, err := pm2VendorCollectIdentities(ctx, root, anchor.Entries, true)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(identities, anchor.Identities) {
		return errors.New("PM2 original Root vendor inode or ctime changed; a chown-only repair is not accepted")
	}
	visible, err := pm2VendorAt(parent, "pm2")
	opened, openErr := pm2VendorStat(root)
	if err != nil || openErr != nil || visible.Dev != opened.Dev || visible.Ino != opened.Ino {
		return errors.New("PM2 original public vendor directory changed during verification")
	}
	return nil
}
