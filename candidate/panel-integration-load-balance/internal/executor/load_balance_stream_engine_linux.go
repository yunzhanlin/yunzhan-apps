//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
	"local/panel/internal/runtimecatalog"
)

type loadBalanceStreamEngineFile struct {
	path   string
	file   *os.File
	before os.FileInfo
	sha    string
}

func (f *loadBalanceStreamEngineFile) current() bool {
	if f == nil || f.file == nil || threatIDSTrustedParents(filepath.Dir(f.path), false) != nil {
		return false
	}
	a, e1 := f.file.Stat()
	b, e2 := os.Lstat(f.path)
	return e1 == nil && e2 == nil && geoStoreStableInfo(f.before, a) && geoStoreStableInfo(a, b)
}

// No path is accepted from Core or a browser. Production callers select only
// reviewed runtimecatalog release CLI/manifest paths or the fixed nft CLI.
func holdLoadBalanceStreamEngineFile(path string, executable bool) (*loadBalanceStreamEngineFile, []byte, error) {
	if os.Geteuid() != 0 || threatIDSTrustedParents(filepath.Dir(path), false) != nil {
		return nil, nil, loadbalancestream.ErrService
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, loadbalancestream.ErrService
	}
	f := &loadBalanceStreamEngineFile{path: path, file: file}
	fail := func() (*loadBalanceStreamEngineFile, []byte, error) {
		file.Close()
		return nil, nil, loadbalancestream.ErrService
	}
	f.before, err = file.Stat()
	limit := int64(128 << 20)
	if !executable {
		limit = 128 << 10
	}
	if err != nil || !f.before.Mode().IsRegular() || f.before.Size() < 1 || f.before.Size() > limit || f.before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || f.before.Mode().Perm()&0022 != 0 {
		return fail()
	}
	st, ok := f.before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || executable && f.before.Mode().Perm()&0111 == 0 {
		return fail()
	}
	if executable {
		var header [20]byte
		if n, err := file.ReadAt(header[:], 0); err != nil || n != len(header) || string(header[:6]) != "\x7fELF\x02\x01" || binary.LittleEndian.Uint16(header[18:]) != map[string]uint16{"amd64": 62, "arm64": 183}[runtime.GOARCH] {
			return fail()
		}
		h := sha256.New()
		if n, err := io.Copy(h, io.LimitReader(file, limit+1)); err != nil || n != f.before.Size() || !f.current() {
			return fail()
		}
		f.sha = hex.EncodeToString(h.Sum(nil))
		return f, nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != f.before.Size() || !f.current() {
		return fail()
	}
	f.sha = core.Hash(string(raw))
	return f, raw, nil
}

type loadBalanceStreamHeldEngine struct {
	release          runtimecatalog.Release
	binary, manifest *loadBalanceStreamEngineFile
}

// Historical native manifests were also written as indented JSON. Their
// contract is bounded unambiguous typed CONTENT, not today's json.Marshal byte
// layout. Preserve and hash the actual original bytes; do not rewrite them.
// New private stream journals/submissions/receipts retain their own independent
// byte-canonical contracts. None of these parsed values is a signature grant.
func validateLoadBalanceStreamEngineManifest(raw []byte, r runtimecatalog.Release, arch string) (RuntimeManifest, error) {
	var installed RuntimeManifest
	if len(raw) == 0 || len(raw) > 128<<10 || r.Family != "nginx" || r.ID != "nginx-1.30.6" && r.ID != "nginx-1.31.5" || arch != "amd64" && arch != "arm64" || decodeProgramQueueJSON(raw, &installed) != nil || installed.Release != r || installed.Architecture != arch || !slices.Contains(installed.Configure, "--with-stream") || !slices.Contains(installed.Configure, "--with-stream_ssl_module") || !slices.Contains(installed.Extensions, "stream") || !slices.Contains(installed.Extensions, "stream_ssl_module") {
		return RuntimeManifest{}, loadbalancestream.ErrService
	}
	when, err := time.Parse(time.RFC3339, installed.InstalledAt)
	if err != nil || when.Year() < 2026 || when.UTC().Format(time.RFC3339) != installed.InstalledAt || when.After(time.Now().Add(time.Second)) {
		return RuntimeManifest{}, loadbalancestream.ErrService
	}
	return installed, nil
}

func (e *loadBalanceStreamHeldEngine) close() {
	if e != nil {
		if e.binary != nil {
			e.binary.file.Close()
		}
		if e.manifest != nil {
			e.manifest.file.Close()
		}
	}
}
func (e *loadBalanceStreamHeldEngine) current() bool {
	return e != nil && e.binary != nil && e.manifest != nil && e.binary.current() && e.manifest.current()
}

// An existing but invalid preferred installation is NOT masked by selecting a
// different engine. Only an actually missing reviewed release may be skipped.
// -V executes the held exact native ELF with fixed argv/environment; it loads
// no caller configuration, starts no master and opens no listener.
func holdLoadBalanceStreamEngine(ctx context.Context) (*loadBalanceStreamHeldEngine, error) {
	return holdLoadBalanceStreamRecordedEngine(ctx, "")
}

// A nonempty selector comes only from a canonical Root-owned original receipt,
// not an RPC path. It prevents a later preferred installation from silently
// substituting a different engine when observing an existing installation.
func holdLoadBalanceStreamRecordedEngine(ctx context.Context, selected string) (*loadBalanceStreamHeldEngine, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return nil, loadbalancestream.ErrService
	}
	if selected != "" && selected != "nginx-1.30.6" && selected != "nginx-1.31.5" {
		return nil, loadbalancestream.ErrService
	}
	for _, id := range []string{"nginx-1.30.6", "nginx-1.31.5"} {
		if selected != "" && selected != id {
			continue
		}
		r, known := runtimecatalog.Find(id)
		if !known || r.Family != "nginx" {
			return nil, loadbalancestream.ErrService
		}
		if _, err := os.Lstat(r.Prefix()); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, loadbalancestream.ErrService
		}
		f, _, err := holdLoadBalanceStreamEngineFile(r.CLI(), true)
		if err != nil {
			return nil, err
		}
		engine := &loadBalanceStreamHeldEngine{release: r, binary: f}
		fail := func() (*loadBalanceStreamHeldEngine, error) { engine.close(); return nil, loadbalancestream.ErrService }
		manifest, raw, err := holdLoadBalanceStreamEngineFile(filepath.Join(r.Prefix(), ".panel-runtime.json"), false)
		if err != nil {
			return fail()
		}
		engine.manifest = manifest
		if _, err := validateLoadBalanceStreamEngineManifest(raw, r, runtime.GOARCH); err != nil {
			return fail()
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		cmd := exec.CommandContext(bounded, "/proc/self/fd/3", "-V")
		cmd.Args[0] = r.CLI()
		cmd.ExtraFiles = []*os.File{f.file}
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		cmd.WaitDelay = time.Second
		output := &boundedBuffer{max: 16384}
		cmd.Stdout, cmd.Stderr = output, output
		err = cmd.Run()
		cancel()
		fields := strings.Fields(output.String())
		if err != nil || output.truncated || !strings.HasPrefix(output.String(), "nginx version: nginx/"+r.Version+"\n") || !slices.Contains(fields, "--with-stream") || !slices.Contains(fields, "--with-stream_ssl_module") || !slices.Contains(fields, "--prefix="+r.Prefix()) || !engine.current() || ctx.Err() != nil {
			return fail()
		}
		return engine, nil
	}
	return nil, loadbalancestream.ErrService
}
