package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"strings"
	"testing"
)

func threatIDSLibraryFixture(t *testing.T, arch string) (*threatIDSLibraryBundle, map[string]string) {
	t.Helper()
	url, err := threatIDSLibraryURL(arch)
	if err != nil {
		t.Fatal(err)
	}
	b := &threatIDSLibraryBundle{URL: url, KeySHA: core.Hash("fixture distro public key"), Catalogs: map[string]string{}, Packages: map[string]threatIDSLibrary{}}
	for _, suite := range []string{"noble", "noble-updates", "noble-security"} {
		b.Catalogs[suite] = core.Hash(suite)
	}
	files := map[string]string{"bin/suricata": core.Hash("fixture ELF"), "licenses/suricata-copyright.txt": core.Hash("copyright"), "licenses/GPL-2.txt": core.Hash("full GPL")}
	for name, spec := range threatIDSEventLibraries {
		version := "2.1.12-stable-9ubuntu2.2"
		depends := "libc6 (>= 2.38)"
		if name == "libevent-pthreads-2.1-7t64" {
			depends = "libc6 (>= 2.34), libevent-core-2.1-7t64 (= " + version + ")"
		}
		filename := "pool/main/libe/libevent/" + name + "_" + version + "_" + arch + ".deb"
		metadata := "Package: " + name + "\nVersion: " + version + "\nArchitecture: " + arch + "\nSize: 1024\nSHA256: " + core.Hash(name) + "\nFilename: " + filename + "\nDepends: " + depends + "\n"
		p, err := parseThreatIDSLibraryMetadata(name, version, arch, metadata)
		if err != nil {
			t.Fatal(err)
		}
		b.Packages[name] = threatIDSLibrary{Package: p, MetadataSHA: core.Hash(metadata), File: spec.SONAME + ".0.1"}
		files["libraries/"+spec.SONAME] = core.Hash(name + " native")
		files["licenses/"+name+"-copyright.txt"] = core.Hash(name + " complete copyright")
	}
	return b, files
}

func TestThreatIDSPrivateLibrariesMetadataClosedIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		b, files := threatIDSLibraryFixture(t, arch)
		if err := validateThreatIDSLibraryBundle("ubuntu-24.04", arch, b, files); err != nil {
			t.Fatal(err)
		}
	}
	name := "libevent-2.1-7t64"
	version := "2.1.12-stable-9ubuntu2.2"
	metadata := "Package: " + name + "\nVersion: " + version + "\nArchitecture: arm64\nSize: 1024\nSHA256: " + core.Hash("package") + "\nFilename: pool/main/libe/libevent/" + name + "_" + version + "_arm64.deb\nDepends: libc6 (>= 2.38)\n"
	if _, err := parseThreatIDSLibraryMetadata(name, version, "arm64", metadata+"\n"+metadata); err != nil {
		t.Fatal("identical APT paragraphs rejected", err)
	}
	for _, bad := range []string{
		metadata + "Size: 1024\n", metadata + "Unknown:\nUnknown: conflicting\n",
		strings.Replace(metadata, "Size: 1024", "Size: 0", 1), strings.Replace(metadata, "Size: 1024", "Size: 8388609", 1),
		strings.Replace(metadata, "SHA256: "+core.Hash("package"), "SHA256: broken", 1),
		strings.Replace(metadata, "pool/main/libe/libevent/", "pool/main/../libevent/", 1),
		strings.Replace(metadata, "Architecture: arm64", "Architecture: amd64", 1),
		strings.Replace(metadata, "_arm64.deb", "_all.deb", 1),
		metadata + "\n" + strings.Replace(metadata, core.Hash("package"), core.Hash("other"), 1),
	} {
		if _, err := parseThreatIDSLibraryMetadata(name, version, "arm64", bad); err == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
	for _, name := range []string{"libc6", "libevent-dev", "suricata", "--option"} {
		if _, err := parseThreatIDSLibraryMetadata(name, version, "arm64", metadata); err == nil {
			t.Fatal("unreviewed private library allowed")
		}
	}
}

func TestThreatIDSPrivateLibrariesBundleRejectsMixedABIAndMissingEvidence(t *testing.T) {
	for _, change := range []func(*threatIDSLibraryBundle, map[string]string){
		func(b *threatIDSLibraryBundle, f map[string]string) { b.URL = "https://unreviewed.invalid/ubuntu" },
		func(b *threatIDSLibraryBundle, f map[string]string) { b.KeySHA = "bad" },
		func(b *threatIDSLibraryBundle, f map[string]string) { delete(b.Catalogs, "noble-security") },
		func(b *threatIDSLibraryBundle, f map[string]string) { b.Catalogs["foreign"] = core.Hash("foreign") },
		func(b *threatIDSLibraryBundle, f map[string]string) { delete(b.Packages, "libevent-core-2.1-7t64") },
		func(b *threatIDSLibraryBundle, f map[string]string) { delete(f, "libraries/libevent_core-2.1.so.7") },
		func(b *threatIDSLibraryBundle, f map[string]string) {
			f["libraries/unreviewed.so"] = core.Hash("foreign")
		},
		func(b *threatIDSLibraryBundle, f map[string]string) {
			n := "libevent-core-2.1-7t64"
			p := b.Packages[n]
			p.Package.Version = "2.1.12-stable-9ubuntu2.1"
			b.Packages[n] = p
		},
		func(b *threatIDSLibraryBundle, f map[string]string) {
			n := "libevent-core-2.1-7t64"
			p := b.Packages[n]
			p.Package.Architecture = "amd64"
			b.Packages[n] = p
		},
		func(b *threatIDSLibraryBundle, f map[string]string) {
			n := "libevent-core-2.1-7t64"
			p := b.Packages[n]
			p.File = "../foreign.so"
			b.Packages[n] = p
		},
		func(b *threatIDSLibraryBundle, f map[string]string) {
			n := "libevent-pthreads-2.1-7t64"
			p := b.Packages[n]
			p.Package.Depends += ", systemd"
			b.Packages[n] = p
		},
		func(b *threatIDSLibraryBundle, f map[string]string) {
			f["licenses/libevent-2.1-7t64-copyright.txt"] = ""
		},
	} {
		b, f := threatIDSLibraryFixture(t, "arm64")
		change(b, f)
		if validateThreatIDSLibraryBundle("ubuntu-24.04", "arm64", b, f) == nil {
			t.Fatal("tampered bundle accepted")
		}
	}
	b, f := threatIDSLibraryFixture(t, "arm64")
	for _, platform := range []string{"debian-13", "ubuntu-22.04", "ubuntu-26.04", "unknown"} {
		if validateThreatIDSLibraryBundle(platform, "arm64", b, f) == nil {
			t.Fatal("borrowed distro ABI accepted")
		}
	}
}

func TestThreatIDSPrivateLibrariesPrefixBindsCompleteCohort(t *testing.T) {
	p := threatIDSPackage{Name: "suricata", Version: "1:8.0.7-0ubuntu0", SHA256: core.Hash("vendor"), Architecture: "arm64"}
	b, _ := threatIDSLibraryFixture(t, "arm64")
	legacy := threatIDSRuntimePrefix(p, nil)
	if legacy != threatIDSPackagePrefixPortable(p) {
		t.Fatal("legacy namespace changed")
	}
	prefix := threatIDSRuntimePrefix(p, b)
	if prefix == legacy || !threatIDSUnitPrefix.MatchString(prefix) {
		t.Fatal("private libraries not bound to prefix")
	}
	encoded, _ := json.Marshal(b)
	var copy threatIDSLibraryBundle
	_ = json.Unmarshal(encoded, &copy)
	if threatIDSRuntimePrefix(p, &copy) != prefix {
		t.Fatal("identity depends on map iteration")
	}
	copy.Catalogs["noble-security"] = core.Hash("another signed catalog")
	if threatIDSRuntimePrefix(p, &copy) == prefix {
		t.Fatal("source identity rebound same private path")
	}
}

func TestThreatIDSPrivateLibrariesHostDependenciesKeepRemainingConstraints(t *testing.T) {
	raw := "libc6 (>= 2.38), libevent-2.1-7t64 (>= 2.1.8-stable), libevent-pthreads-2.1-7t64 (>= 2.1.8-stable), libhiredis1.1.0 (>= 1.2.0), python3-yaml"
	wanted := "libc6 (>= 2.38), libhiredis1.1.0 (>= 1.2.0), python3-yaml"
	if threatIDSHostLibraryDependencies(raw, true) != wanted || threatIDSHostLibraryDependencies(raw, false) != raw {
		t.Fatal("ABI constraints or legacy behavior lost")
	}
	if deps, err := threatIDSDependencies(wanted); err != nil || len(deps) != 2 {
		t.Fatal(deps, err)
	}
}

func TestThreatIDSPrivateLibrariesUnitsFixedEnvironmentAndLegacyBytes(t *testing.T) {
	prefix := "apt-0123456789abcdef"
	for _, render := range []func(...bool) (string, error){
		func(v ...bool) (string, error) {
			return threatIDSGatedUnit(prefix, "/opt/panel/current/bin/panel-executor", v...)
		},
		func(v ...bool) (string, error) { return threatIDSSyntaxUnit(prefix, v...) },
	} {
		old, err := render()
		if err != nil {
			t.Fatal(err)
		}
		same, err := render(false)
		if err != nil || same != old || strings.Contains(old, "LD_LIBRARY_PATH") {
			t.Fatal("legacy unit changed")
		}
		private, err := render(true)
		line := "Environment=\"LD_LIBRARY_PATH=/opt/panel/app-modules/network-threat-detection/" + prefix + "/libraries\" \"LD_PRELOAD=\" \"LD_AUDIT=\" \"LD_DEBUG=\"\n"
		if err != nil || strings.Count(private, line) != 1 || strings.Replace(private, line, "", 1) != old {
			t.Fatal("private loader changes unrelated unit permissions/argv")
		}
		if _, err := render(true, false); err == nil {
			t.Fatal("ambiguous private library parameter accepted")
		}
	}
}

func threatIDSLibraryTar(t *testing.T, change func(*tar.Header), duplicate bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for i, file := range []string{"./usr/lib/aarch64-linux-gnu/libevent-2.1.so.7.0.1", "./usr/share/doc/libevent-2.1-7t64/copyright"} {
		h := &tar.Header{Name: file, Mode: 0644, Typeflag: tar.TypeReg, Size: 3}
		if i == 0 && change != nil {
			change(h)
		}
		if err := writer.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := writer.Write([]byte("abc")); err != nil {
				t.Fatal(err)
			}
		}
		if duplicate && i == 0 {
			if err := writer.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("abc")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestThreatIDSPrivateLibrariesArchiveNeverExtractsLinksOrForeignPaths(t *testing.T) {
	files, err := readThreatIDSLibraryFiles(context.Background(), bytes.NewReader(threatIDSLibraryTar(t, nil, false)), "libevent-2.1-7t64", "arm64")
	if err != nil || len(files) != 2 || string(files["copyright"]) != "abc" || string(files["libevent-2.1.so.7.0.1"]) != "abc" {
		t.Fatal(files, err)
	}
	for _, change := range []func(*tar.Header){
		func(h *tar.Header) { h.Name = "../../usr/lib/aarch64-linux-gnu/libevent-2.1.so.7.0.1" },
		func(h *tar.Header) { h.Name = "./usr/lib/x86_64-linux-gnu/libevent-2.1.so.7.0.1" },
		func(h *tar.Header) { h.Typeflag = tar.TypeSymlink; h.Linkname = "/etc/passwd"; h.Size = 0 },
		func(h *tar.Header) { h.Typeflag = tar.TypeLink; h.Linkname = "foreign"; h.Size = 0 },
		func(h *tar.Header) { h.Uid = 999 }, func(h *tar.Header) { h.Gid = 999 },
		func(h *tar.Header) { h.Mode = 0666 }, func(h *tar.Header) { h.Mode = 04644 },
	} {
		if _, err := readThreatIDSLibraryFiles(context.Background(), bytes.NewReader(threatIDSLibraryTar(t, change, false)), "libevent-2.1-7t64", "arm64"); err == nil {
			t.Fatal("unsafe private library stream accepted")
		}
	}
	if _, err := readThreatIDSLibraryFiles(context.Background(), bytes.NewReader(threatIDSLibraryTar(t, nil, true)), "libevent-2.1-7t64", "arm64"); err == nil {
		t.Fatal("duplicate native selected library accepted")
	}
}
