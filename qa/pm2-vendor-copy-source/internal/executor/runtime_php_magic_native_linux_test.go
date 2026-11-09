//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"io"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeCompilerNativePHPFileinfoByteEquivalentUnderMemoryLimit(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_PHP_MAGIC_NATIVE") != "1" {
		t.Skip("explicit pinned official source and finite-memory native compiler service required")
	}
	id := os.Getenv("PANEL_QA_RUNTIME_PHP_MAGIC_RELEASE")
	spec, ok := runtimeMagicSpecification(id)
	r, found := runtimecatalog.Find(id)
	if !ok || !found || r.SHA256 != spec.archiveSHA || runtimecatalog.RuntimeInstallAdmission(r) != nil {
		t.Fatal("closed reviewed official PHP source identity missing")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("native supervisor confinement changed", identity)
	}
	own, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	cgroup, err := decodeRuntimeCompilerCgroup(string(own))
	if err != nil {
		t.Fatal(err)
	}
	cg := filepath.Join("/sys/fs/cgroup", cgroup)
	maximum, err := os.ReadFile(filepath.Join(cg, "memory.max"))
	swap, swapErr := os.ReadFile(filepath.Join(cg, "memory.swap.max"))
	if err != nil || swapErr != nil || string(maximum) != "805306368\n" || string(swap) != "0\n" || os.Getenv("GOMEMLIMIT") != "128MiB" {
		t.Fatal("768 MiB native compiler ceiling or no-swap scope not actually installed", err, swapErr)
	}
	const fixture = "/run/panel-runtime-collection24amv"
	archive := filepath.Join(fixture, id+".tar.gz")
	f, err := os.OpenFile(archive, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil || !runtimeBuildPrivateFile(st) || st.Size() < 1 || st.Size() > 64<<20 {
		f.Close()
		t.Fatal("official archive private identity changed", err)
	}
	digest := sha256.New()
	_, err = io.Copy(digest, f)
	f.Close()
	if err != nil || hex.EncodeToString(digest.Sum(nil)) != spec.archiveSHA {
		t.Fatal("official archive does not match independent pinned source", err)
	}
	work := filepath.Join(fixture, "official-magic-work")
	if err := os.Mkdir(work, 0755); err != nil {
		t.Fatal(err)
	}
	if err := extractSource(archive, work); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "php-"+r.Version)
	transforms, err := prepareRuntimePHPBuildSource(r, source)
	if err != nil || len(transforms) != 1 || transforms[0].DataSHA256 != spec.dataSHA {
		t.Fatal("actual normal build preparation failed", err)
	}
	original, err := os.ReadFile(filepath.Join(source, runtimeMagicPath+".upstream-"+spec.inputSHA))
	if err != nil {
		t.Fatal(err)
	}
	originalSHA := sha256.Sum256(original)
	if hex.EncodeToString(originalSHA[:]) != spec.inputSHA {
		t.Fatal("original official generated file not byte-exact retained")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if _, err := RunCommand(ctx, "/usr/bin/chown", "-R", "panel-build:panel-build", work); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(fixture, "official-magic-build.log")
	flags := []string{"--prefix=" + r.Prefix(), "--with-config-file-path=" + r.Prefix() + "/etc", "--with-config-file-scan-dir=" + r.Prefix() + "/etc/conf.d", "--enable-fpm", "--disable-cgi", "--disable-phpdbg", "--without-pear", "--with-openssl", "--with-curl", "--with-zlib", "--enable-mbstring", "--enable-bcmath", "--enable-sockets", "--enable-pcntl", "--enable-exif", "--enable-ftp", "--with-mysqli=mysqlnd", "--with-pdo-mysql=mysqlnd", "--with-zip", "--enable-intl", "--enable-gd", "--with-jpeg", "--with-freetype"}
	if err := buildCommand(ctx, source, log, source+"/configure", flags...); err != nil {
		t.Fatal("genuine configure failed", err)
	}
	// No -O0/-O1, disabled extension, patched compiler, shell command or bypass.
	// The normal generated target retains all original -O2 / hardening flags.
	if err := buildCommand(ctx, source, log, "/usr/bin/make", "-j1", "ext/fileinfo/libmagic/apprentice.lo"); err != nil {
		t.Fatal("actual original fileinfo compilation exceeded finite memory or failed", err)
	}
	var checked []string
	for _, leaf := range []string{"ext/fileinfo/libmagic/apprentice.o", "ext/fileinfo/libmagic/.libs/apprentice.o"} {
		path := filepath.Join(source, leaf)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() < int64(spec.dataBytes) || st.Size() > 32<<20 {
			f.Close()
			t.Fatal("native object identity or capacity invalid", err)
		}
		raw, err := io.ReadAll(io.LimitReader(f, 32<<20+1))
		f.Close()
		if err != nil || int64(len(raw)) != st.Size() {
			t.Fatal("native object read changed", err)
		}
		object, err := elf.NewFile(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		wantMachine := elf.EM_AARCH64
		if runtime.GOARCH == "amd64" {
			wantMachine = elf.EM_X86_64
		}
		if object.Type != elf.ET_REL || object.Machine != wantMachine {
			t.Fatal("wrong native architecture or object type")
		}
		symbols, err := object.Symbols()
		if err != nil || len(symbols) > 10000 {
			t.Fatal("native symbols unavailable or excessive", err)
		}
		found := 0
		for _, symbol := range symbols {
			if symbol.Name != "php_magic_database" {
				continue
			}
			found++
			if elf.ST_TYPE(symbol.Info) != elf.STT_OBJECT || symbol.Size != uint64(spec.dataBytes) || int(symbol.Section) >= len(object.Sections) {
				t.Fatal("compiler changed original array size or added padding/NUL")
			}
			section := object.Sections[symbol.Section]
			data, err := section.Data()
			if err != nil || symbol.Value < section.Addr || symbol.Value-section.Addr > uint64(len(data)) || symbol.Size > uint64(len(data))-(symbol.Value-section.Addr) {
				t.Fatal("native symbol is outside its exact bounded section")
			}
			offset := symbol.Value - section.Addr
			sum := sha256.Sum256(data[offset : offset+symbol.Size])
			if hex.EncodeToString(sum[:]) != spec.dataSHA {
				t.Fatal("actual compiler changed a byte of the official magic database")
			}
		}
		object.Close()
		if found != 1 {
			t.Fatal("native object lacks one exact official database identity")
		}
		checked = append(checked, leaf)
	}
	if len(checked) == 0 {
		t.Fatal("normal target emitted no native object")
	}
	logBytes, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(logBytes), " -O2 ") || !strings.Contains(string(logBytes), "compiler-collection-v2 member_snapshots=0 ") {
		t.Fatal("original optimization and fully collected native command witnesses missing", err)
	}
	if empty, err := compilerHasNoChildren(); err != nil || !empty {
		t.Fatal("actual compiler left live or unreaped children", err)
	}
	logSHA := sha256.Sum256(logBytes)
	proof, err := json.MarshalIndent(map[string]any{
		"passed": true, "release": id, "source_archive_sha256": spec.archiveSHA, "build_transform": transforms[0],
		"actual_compiler_ELF_database_bytes_and_original_size_verified": true, "native_objects": checked,
		"memory_max_bytes": 768 << 20, "memory_swap_max_bytes": 0, "Go_memory_limit": "128MiB",
		"original_O2_and_all_extensions_preserved": true, "compile_log_sha256": hex.EncodeToString(logSHA[:]),
		"native_scope_fully_collected": true, "runtime_or_application_installed": false, "all50_commercial": false,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(fixture, "official-magic-proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
}
