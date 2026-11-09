//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

type RuntimePHPArtifact struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Root-produced provenance for a NEW source build, never an adoption of an
// existing prefix. Optional for backwards-compatible inventory; an old or
// absent seal grants no superseded-OOM upgrade admission.
type RuntimePHPPublication struct {
	Format       int                           `json:"format"`
	JobID        string                        `json:"job_id"`
	SourceSHA256 string                        `json:"source_sha256"`
	Artifacts    map[string]RuntimePHPArtifact `json:"artifacts"`
}

var errRuntimePHPPublication = errors.New("PHP 发布来源、程序摘要或只读文件身份不可核实，原记录与文件保留")

type runtimePHPHeldFile struct {
	name string
	file *os.File
	info os.FileInfo
}

type runtimePHPHeldTree struct {
	root      *os.Root
	prefix    string
	dirs      []programQueueSnapshot
	files     []runtimePHPHeldFile
	artifacts map[string]RuntimePHPArtifact
	manifest  []byte
}

func (t *runtimePHPHeldTree) close() {
	for _, f := range t.files {
		f.file.Close()
	}
	if t.root != nil {
		t.root.Close()
	}
}

func runtimePHPArtifactFile(info os.FileInfo, manifest bool) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	mode, limit := os.FileMode(0755), int64(256<<20)
	if manifest {
		mode, limit = 0644, 64<<10
	}
	return ok && info.Mode() == mode && st.Uid == 0 && st.Nlink == 1 && info.Size() > 0 && info.Size() <= limit
}

func runtimePHPArtifactELF(header []byte, arch string) bool {
	machine := uint16(0)
	if arch == "amd64" {
		machine = 62
	} else if arch == "arm64" {
		machine = 183
	}
	return machine != 0 && len(header) == 64 && bytes.Equal(header[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) && (binary.LittleEndian.Uint16(header[16:18]) == 2 || binary.LittleEndian.Uint16(header[16:18]) == 3) && binary.LittleEndian.Uint16(header[18:20]) == machine && binary.LittleEndian.Uint32(header[20:24]) == 1 && binary.LittleEndian.Uint16(header[52:54]) == 64
}

// Bounded streaming: never read a potentially 256 MiB executable into memory.
// Cancellation is checked per 32 KiB and metadata/name identity is rechecked.
func runtimePHPHashFile(ctx context.Context, f *os.File) (string, error) {
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var total int64
	for {
		if ctx.Err() != nil {
			return "", errRuntimePHPPublication
		}
		n, err := f.Read(buf)
		total += int64(n)
		if total > 256<<20 {
			return "", errRuntimePHPPublication
		}
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			return hex.EncodeToString(h.Sum(nil)), nil
		}
		if err != nil {
			return "", errRuntimePHPPublication
		}
	}
}

// The production callers independently bind the fixed complete ancestry.
// This unexported leaf reader also permits isolated Root-owned test trees.
func holdRuntimePHPFiles(ctx context.Context, prefix, arch string, withManifest bool) (_ *runtimePHPHeldTree, ret error) {
	t := &runtimePHPHeldTree{prefix: prefix, artifacts: map[string]RuntimePHPArtifact{}}
	defer func() {
		if ret != nil {
			t.close()
		}
	}()
	if ctx.Err() != nil || !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix {
		return nil, errRuntimePHPPublication
	}
	for _, name := range []string{prefix, filepath.Join(prefix, "bin"), filepath.Join(prefix, "sbin")} {
		if ownedRuntimePath(name, true) != nil {
			return nil, errRuntimePHPPublication
		}
		info, err := os.Lstat(name)
		if err != nil {
			return nil, errRuntimePHPPublication
		}
		t.dirs = append(t.dirs, programQueueSnapshot{path: name, info: info})
	}
	var err error
	t.root, err = os.OpenRoot(prefix)
	if err != nil {
		return nil, errRuntimePHPPublication
	}
	held, err := t.root.Stat(".")
	if err != nil || !programQueueSame(t.dirs[0].info, held) {
		return nil, errRuntimePHPPublication
	}
	names := []string{"bin/php", "sbin/php-fpm"}
	if withManifest {
		names = append(names, ".panel-runtime.json")
	}
	for _, name := range names {
		manifest := name == ".panel-runtime.json"
		f, err := t.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, errRuntimePHPPublication
		}
		t.files = append(t.files, runtimePHPHeldFile{name: name, file: f})
		info, er := f.Stat()
		if er != nil || !runtimePHPArtifactFile(info, manifest) {
			return nil, errRuntimePHPPublication
		}
		t.files[len(t.files)-1].info = info
		if manifest {
			t.manifest, err = io.ReadAll(io.LimitReader(f, 64<<10+1))
			if err != nil || int64(len(t.manifest)) != info.Size() {
				return nil, errRuntimePHPPublication
			}
		} else {
			header := make([]byte, 64)
			if _, err = f.ReadAt(header, 0); err != nil || !runtimePHPArtifactELF(header, arch) {
				return nil, errRuntimePHPPublication
			}
			digest, err := runtimePHPHashFile(ctx, f)
			if err != nil {
				return nil, err
			}
			t.artifacts[name] = RuntimePHPArtifact{Bytes: info.Size(), SHA256: digest}
		}
	}
	if !t.current(ctx) {
		return nil, errRuntimePHPPublication
	}
	return t, nil
}

func (t *runtimePHPHeldTree) current(ctx context.Context) bool {
	if ctx.Err() != nil || t == nil || t.root == nil {
		return false
	}
	for _, d := range t.dirs {
		info, err := os.Lstat(d.path)
		if err != nil || !programQueueSame(d.info, info) {
			return false
		}
	}
	held, err := t.root.Stat(".")
	if err != nil || !programQueueSame(t.dirs[0].info, held) {
		return false
	}
	for _, f := range t.files {
		held, e1 := f.file.Stat()
		named, e2 := t.root.Lstat(f.name)
		if e1 != nil || e2 != nil || !programQueueSame(f.info, held) || !programQueueSame(f.info, named) {
			return false
		}
	}
	return true
}

// Filesystems may retain identical mtime/ctime for a rapid same-size write.
// Metadata is a useful repeated identity check, not final byte authority.
// Rehash the held descriptors immediately before producer/upgrade admission,
// within the existing caller deadline and without reading whole binaries into
// memory. The build/start read leases exclude normal concurrent publishers.
func (t *runtimePHPHeldTree) bytesCurrent(ctx context.Context) bool {
	if !t.current(ctx) {
		return false
	}
	for _, f := range t.files {
		if _, err := f.file.Seek(0, io.SeekStart); err != nil {
			return false
		}
		want := t.artifacts[f.name].SHA256
		if f.name == ".panel-runtime.json" {
			sum := sha256.Sum256(t.manifest)
			want = hex.EncodeToString(sum[:])
		}
		got, err := runtimePHPHashFile(ctx, f.file)
		if err != nil || got != want {
			return false
		}
	}
	return t.current(ctx)
}

func runtimePHPPublicationAncestry(prefix string) ([]programQueueSnapshot, error) {
	var out []programQueueSnapshot
	for p := prefix; ; p = filepath.Dir(p) {
		if ownedRuntimePath(p, true) != nil {
			return nil, errRuntimePHPPublication
		}
		info, err := os.Lstat(p)
		if err != nil {
			return nil, errRuntimePHPPublication
		}
		out = append(out, programQueueSnapshot{path: p, info: info})
		if p == "/" {
			return out, nil
		}
	}
}

func runtimePHPAncestryCurrent(snapshots []programQueueSnapshot) bool {
	if len(snapshots) == 0 {
		return false
	}
	for _, snapshot := range snapshots {
		info, err := os.Lstat(snapshot.path)
		if err != nil || ownedRuntimePath(snapshot.path, true) != nil || !programQueueSame(snapshot.info, info) {
			return false
		}
	}
	return true
}

func sealRuntimePHPPublication(ctx context.Context, r runtimecatalog.Release, id, prefix string, run Command) (*RuntimePHPPublication, error) {
	official, found := runtimecatalog.Find(r.ID)
	if ctx.Err() != nil || !found || official != r || r.Family != "php" || runtimecatalog.RuntimeInstallAdmission(r) != nil || !core.ValidID(id) || prefix != r.Prefix()+".pending-"+id || run == nil {
		return nil, errRuntimePHPPublication
	}
	ancestry, err := runtimePHPPublicationAncestry(prefix)
	if err != nil {
		return nil, err
	}
	return sealRuntimePHPPublicationTree(ctx, r, id, prefix, ancestry, run)
}

// Only the fixed-path producer above is used by InstallJob. This isolated
// component seam lets tests prove hashing and refusal without publishing a
// production runtime, manufacturing a store receipt or changing old records.
func sealRuntimePHPPublicationTree(ctx context.Context, r runtimecatalog.Release, id, prefix string, ancestry []programQueueSnapshot, run Command) (*RuntimePHPPublication, error) {
	official, found := runtimecatalog.Find(r.ID)
	if !found || r != official || r.Family != "php" || runtimecatalog.RuntimeInstallAdmission(r) != nil || len(ancestry) == 0 || ancestry[0].path != prefix || !runtimePHPAncestryCurrent(ancestry) || !core.ValidID(id) || run == nil {
		return nil, errRuntimePHPPublication
	}
	tree, err := holdRuntimePHPFiles(ctx, prefix, runtime.GOARCH, false)
	if err != nil {
		return nil, err
	}
	defer tree.close()
	version, err := run(ctx, filepath.Join(prefix, "sbin/php-fpm"), "-n", "-v")
	if err != nil || !runtimePHPFPMVersionMatches(r, version) || !tree.bytesCurrent(ctx) || !runtimePHPAncestryCurrent(ancestry) {
		return nil, errRuntimePHPPublication
	}
	return &RuntimePHPPublication{Format: 1, JobID: id, SourceSHA256: r.SHA256, Artifacts: tree.artifacts}, nil
}

func runtimePHPFPMVersionMatches(r runtimecatalog.Release, version string) bool {
	official, found := runtimecatalog.Find(r.ID)
	if !found || official != r || r.Family != "php" || len(version) == 0 || len(version) > 4096 || strings.ContainsAny(version, "\x00\r") {
		return false
	}
	lines := strings.Split(strings.TrimSpace(version), "\n")
	prefix := "PHP " + r.Version + " (fpm-fcgi)"
	return len(lines) <= 4 && strings.HasPrefix(lines[0], prefix) && (len(lines[0]) == len(prefix) || lines[0][len(prefix)] == ' ')
}
