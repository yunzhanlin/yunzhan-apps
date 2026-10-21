//go:build linux

package executor

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Minimal synthetic dynamic ELF, never executed and never capture evidence.
func threatIDSLibraryELFFixture(name, arch string, extra elf.DynTag, foreign bool) []byte {
	spec := threatIDSEventLibraries[name]
	strtab := []byte{0}
	add := func(s string) uint64 {
		at := uint64(len(strtab))
		strtab = append(strtab, []byte(s)...)
		strtab = append(strtab, 0)
		return at
	}
	tags := [][2]uint64{{uint64(elf.DT_SONAME), add(spec.SONAME)}, {uint64(elf.DT_NEEDED), add("libc.so.6")}}
	tags = append(tags, [2]uint64{uint64(elf.DT_NEEDED), add(map[string]string{"amd64": "ld-linux-x86-64.so.2", "arm64": "ld-linux-aarch64.so.1"}[arch])})
	if name == "libevent-pthreads-2.1-7t64" {
		tags = append(tags, [2]uint64{uint64(elf.DT_NEEDED), add("libevent_core-2.1.so.7")})
	}
	if foreign {
		tags = append(tags, [2]uint64{uint64(elf.DT_NEEDED), add("foreign-plugin.so")})
	}
	if extra != 0 {
		tags = append(tags, [2]uint64{uint64(extra), add("/untrusted")})
	}
	tags = append(tags, [2]uint64{0, 0})
	image := make([]byte, 1024)
	copy(image, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	put16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(image[at:], v) }
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(image[at:], v) }
	put64 := func(at int, v uint64) { binary.LittleEndian.PutUint64(image[at:], v) }
	put16(16, uint16(elf.ET_DYN))
	put16(18, uint16(map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[arch]))
	put32(20, 1)
	put64(40, 64)
	put16(52, 64)
	put16(58, 64)
	put16(60, 3)
	put32(128+4, uint32(elf.SHT_STRTAB))
	put64(128+24, 256)
	put64(128+32, uint64(len(strtab)))
	put32(192+4, uint32(elf.SHT_DYNAMIC))
	put64(192+24, 512)
	put64(192+32, uint64(16*len(tags)))
	put32(192+40, 1)
	put64(192+56, 16)
	copy(image[256:], strtab)
	for i, tag := range tags {
		put64(512+16*i, tag[0])
		put64(520+16*i, tag[1])
	}
	return image
}

func TestThreatIDSPrivateLibrariesELFRejectsForeignArchitectureLoaderAndDependencies(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for name := range threatIDSEventLibraries {
			image := threatIDSLibraryELFFixture(name, arch, 0, false)
			if err := validateThreatIDSEventELF(image, name, arch); err != nil {
				t.Fatal(name, arch, err)
			}
			other := map[string]string{"amd64": "arm64", "arm64": "amd64"}[arch]
			if validateThreatIDSEventELF(image, name, other) == nil || validateThreatIDSEventELF(image, "libc6", arch) == nil {
				t.Fatal("foreign ELF allowed")
			}
			// Exact native loader only. Mutating the already present string to
			// a same-length foreign name must not widen to arbitrary ld-* libs.
			wrongLoader := append([]byte(nil), image...)
			wanted := map[string]string{"amd64": "ld-linux-x86-64.so.2", "arm64": "ld-linux-aarch64.so.1"}[arch]
			at := bytes.Index(wrongLoader, []byte(wanted))
			if at < 0 {
				t.Fatal("loader fixture missing")
			}
			wrongLoader[at] = 'x'
			if validateThreatIDSEventELF(wrongLoader, name, arch) == nil {
				t.Fatal("unknown loader accepted")
			}
			for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_AUDIT, elf.DT_DEPAUDIT, elf.DT_FILTER, elf.DT_AUXILIARY} {
				if validateThreatIDSEventELF(threatIDSLibraryELFFixture(name, arch, tag, false), name, arch) == nil {
					t.Fatal("loader override allowed", tag)
				}
			}
			if validateThreatIDSEventELF(threatIDSLibraryELFFixture(name, arch, 0, true), name, arch) == nil {
				t.Fatal("foreign dependency allowed")
			}
			image[16] = byte(elf.ET_EXEC)
			if validateThreatIDSEventELF(image, name, arch) == nil {
				t.Fatal("executable substituted for library")
			}
		}
	}
}

// Opt-in readonly packages/aliases, authenticated by the separate QA input
// preparer. Never infer package authentication from an ELF-shaped fixture.
func threatIDSActualLibraryQA(t *testing.T) string {
	t.Helper()
	const root = "/run/panel-private-ids-libelf-qa"
	if os.Getenv("PANEL_THREAT_IDS_LIBRARY_ELF_QA") != root {
		t.Skip("explicit authenticated readonly native library inputs required")
	}
	return root
}

func TestThreatIDSPrivateLibrariesActualNativeELFClosure(t *testing.T) {
	root := threatIDSActualLibraryQA(t)
	for name, spec := range threatIDSEventLibraries {
		data, err := os.ReadFile(filepath.Join(root, "libraries", spec.SONAME))
		if err != nil || len(data) > 8<<20 {
			t.Fatal("bounded actual library", err)
		}
		if err := validateThreatIDSEventELF(data, name, runtime.GOARCH); err != nil {
			t.Fatal(name, err)
		}
	}
}

func TestThreatIDSPrivateLibrariesActualPackageOrdinaryELFAndFullCopyright(t *testing.T) {
	root := threatIDSActualLibraryQA(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for name, spec := range threatIDSEventLibraries {
		files, err := threatIDSDebSelected(ctx, filepath.Join(root, "packages", name+".deb"), func(ctx context.Context, input io.Reader) (map[string][]byte, error) {
			return readThreatIDSLibraryFiles(ctx, input, name, runtime.GOARCH)
		})
		if err != nil || len(files) != 2 || len(files["copyright"]) < 1024 {
			t.Fatal("actual package lacks ordinary selected ELF or complete copyright", name, err)
		}
		canonical, err := os.ReadFile(filepath.Join(root, "libraries", spec.SONAME))
		if err != nil {
			t.Fatal(err)
		}
		selected := false
		for file, data := range files {
			if file != "copyright" {
				selected = true
				if !bytes.Equal(data, canonical) || validateThreatIDSEventELF(data, name, runtime.GOARCH) != nil {
					t.Fatal("original package stream differs from authenticated native library", name)
				}
			}
		}
		if !selected {
			t.Fatal("actual package selected no native library")
		}
	}
}

func threatIDSPrivateRuntimeFixture(t *testing.T) threatIDSRuntime {
	t.Helper()
	libraries, files := threatIDSLibraryFixture(t, runtime.GOARCH)
	p := threatIDSPackage{"suricata", "1:8.0.7-0ubuntu0", runtime.GOARCH, core.Hash("vendor package"), 1024, "libc6 (>= 2.38), libevent-2.1-7t64 (>= 2.1.8-stable), libevent-pthreads-2.1-7t64 (>= 2.1.8-stable)", "pool/main/s/suricata/suricata_8.0.7-0ubuntu0_" + runtime.GOARCH + ".deb"}
	profile, err := threatIDSRepositoryFor("ubuntu-24.04", runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return threatIDSRuntime{Format: 3, Prefix: threatIDSRuntimePrefix(p, libraries), Platform: "ubuntu-24.04", Package: p, Files: files, Libraries: libraries, Source: &threatIDSPackageSource{URL: profile.URL, Suite: profile.Suite, KeySHA: core.Hash(profile.Key), CatalogSHA: core.Hash("signed vendor catalog"), MetadataSHA: core.Hash("vendor metadata")}}
}

func TestThreatIDSPrivateLibrariesRuntimeHeaderRejectsLegacyRelabelAndUnknownFile(t *testing.T) {
	v := threatIDSPrivateRuntimeFixture(t)
	if err := validateThreatIDSRuntimeHeader(v); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*threatIDSRuntime){
		func(v *threatIDSRuntime) { v.Format = 2 }, func(v *threatIDSRuntime) { v.Format = 1 },
		func(v *threatIDSRuntime) { v.Libraries = nil }, func(v *threatIDSRuntime) { v.Source = nil },
		func(v *threatIDSRuntime) { v.Prefix = threatIDSPackagePrefix(v.Package) },
		func(v *threatIDSRuntime) { v.Files["libraries/foreign.so"] = core.Hash("foreign") },
		func(v *threatIDSRuntime) { v.Platform = "ubuntu-22.04" },
	} {
		copy := threatIDSPrivateRuntimeFixture(t)
		change(&copy)
		if validateThreatIDSRuntimeHeader(copy) == nil {
			t.Fatal("tampered runtime accepted")
		}
	}
}

func TestThreatIDSPrivateLibrariesInstalledABIAndCandidateVersionConstraints(t *testing.T) {
	v := threatIDSPrivateRuntimeFixture(t)
	calls := 0
	s := New(Config{SystemRoot: t.TempDir(), Run: func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/bin/dpkg" || len(args) != 4 || args[0] != "--compare-versions" || args[1] != "2.1.12-stable-9ubuntu2.2" {
			t.Fatalf("unreviewed library command %s %v", name, args)
		}
		calls++
		return "", nil
	}})
	if err := s.threatIDSCheckPrivateLibraryConstraints(context.Background(), v.Package.Depends, v.Libraries); err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "", fmt.Errorf("older candidate") }
	if s.threatIDSCheckPrivateLibraryConstraints(context.Background(), v.Package.Depends, v.Libraries) == nil {
		t.Fatal("unsatisfied candidate version accepted")
	}
}

func TestThreatIDSPrivateLibrariesProcessEnvironmentAndKernelMappingIdentity(t *testing.T) {
	s := New(Config{SystemRoot: t.TempDir()})
	v := threatIDSPrivateRuntimeFixture(t)
	base := s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection", v.Prefix, "libraries"))
	procRoot := s.systemPath("/proc")
	proc := filepath.Join(procRoot, "42")
	if err := os.MkdirAll(base, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proc, 0700); err != nil {
		t.Fatal(err)
	}
	maps := ""
	firstPath := ""
	for _, spec := range threatIDSEventLibraries {
		path := filepath.Join(base, spec.SONAME)
		if firstPath == "" {
			firstPath = path
		}
		if err := atomicWrite(path, []byte("fixture mapped ELF identity"), 0644); err != nil {
			t.Fatal(err)
		}
		info, _ := os.Lstat(path)
		st := info.Sys().(*syscall.Stat_t)
		maps += fmt.Sprintf("00001000-00002000 r-xp 00000000 %02x:%02x %d %s\n", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino, path)
	}
	env := "LANG=C\x00LD_LIBRARY_PATH=" + base + "\x00LD_PRELOAD=\x00LD_AUDIT=\x00LD_DEBUG=\x00"
	write := func(environment, mappings string) {
		t.Helper()
		if err := atomicWrite(filepath.Join(proc, "environ"), []byte(environment), 0600); err != nil {
			t.Fatal(err)
		}
		if err := atomicWrite(filepath.Join(proc, "maps"), []byte(mappings), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(env, maps)
	if err := s.threatIDSProcessPrivateLibraries(procRoot, 42, v); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"LANG=C\x00", env + "LD_LIBRARY_PATH=" + base + "\x00", strings.Replace(env, "LD_PRELOAD=\x00", "LD_PRELOAD=foreign.so\x00", 1), strings.Replace(env, base, "/usr/lib", 1)} {
		write(bad, maps)
		if s.threatIDSProcessPrivateLibraries(procRoot, 42, v) == nil {
			t.Fatal("wrong loader environment accepted")
		}
	}
	for _, bad := range []string{strings.Replace(maps, firstPath, "/usr/lib/"+filepath.Base(firstPath)+".0.1", 1), strings.Replace(maps, firstPath, firstPath+" (deleted)", 1), "", strings.Split(maps, "\n")[0] + "\n", strings.Replace(maps, "r-xp 00000000", "r-xp 00000000 broken", 1)} {
		write(env, bad)
		if s.threatIDSProcessPrivateLibraries(procRoot, 42, v) == nil {
			t.Fatal("wrong kernel mapping accepted")
		}
	}
}

func TestThreatIDSPrivateLibrariesRuntimeTreeOrdinaryAliasesAndCompleteSource(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	v := threatIDSPrivateRuntimeFixture(t)
	// Header fixtures cover Ubuntu identity; actual tree validation additionally
	// requires the current host ABI, so this fixture is explicitly Ubuntu-only.
	if runtimecatalog.HostPlatform() != "ubuntu-24.04" {
		t.Skip("actual Ubuntu 24.04 ABI tree fixture")
	}
	base := s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection", v.Prefix))
	native, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"bin/suricata": native, "licenses/GPL-2.txt": []byte("full GPL identity fixture"), "licenses/suricata-copyright.txt": []byte("copyright identity fixture")}
	for name, spec := range threatIDSEventLibraries {
		files["libraries/"+spec.SONAME] = threatIDSLibraryELFFixture(name, runtime.GOARCH, 0, false)
		files["licenses/"+name+"-copyright.txt"] = []byte("full libevent BSD copyright identity fixture")
	}
	for name, data := range files {
		path := filepath.Join(base, name)
		if err := threatIDSTrustedParents(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0644)
		if name == "bin/suricata" {
			mode = 0755
		}
		if err := atomicWrite(path, data, mode); err != nil {
			t.Fatal(err)
		}
		v.Files[name] = core.Hash(string(data))
	}
	if err := moduleWrite(filepath.Join(base, "runtime-manifest.json"), v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.validateThreatIDSRuntime(v); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "libraries/libevent_core-2.1.so.7")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.validateThreatIDSRuntime(v); err == nil {
		t.Fatal("modified private ELF accepted")
	}
	if err := atomicWrite(path, original, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := s.validateThreatIDSRuntime(v); err == nil {
		t.Fatal("writable private library accepted")
	}
	if err := atomicWrite(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(base, "libraries/foreign.so"), []byte("foreign"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.validateThreatIDSRuntime(v); err == nil {
		t.Fatal("unrecorded private library adopted")
	}
	var manifest threatIDSRuntime
	b, _ := os.ReadFile(filepath.Join(base, "runtime-manifest.json"))
	if json.Unmarshal(b, &manifest) != nil || manifest.Format != 3 {
		t.Fatal("source fixture mutated")
	}
}
