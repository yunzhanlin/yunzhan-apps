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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
)

// Fresh official extraction/configure/Zend compilation ONLY. No old failed
// work, installed prefix, Core request, publication, service or site mutation.
func TestRuntimeCompilerNativePHPZendMeasuredOneGiBPolicy(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_PHP_MEMORY_1G_NATIVE") != "1" {
		t.Skip("explicit fresh official archive and new private measured1GiB confinement required")
	}
	id := os.Getenv("PANEL_QA_RUNTIME_PHP_GC_RELEASE")
	r, found := runtimecatalog.Find(id)
	spec, selected := runtimeMagicSpecification(id)
	if !found || !selected || r.SHA256 != spec.archiveSHA || runtimecatalog.RuntimeInstallAdmission(r) != nil {
		t.Fatal("original selected official source identity changed")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" || os.Getenv("GOMEMLIMIT") != "128MiB" {
		t.Fatal("original native supervisor identity or Go budget changed", identity)
	}
	group, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	cgroup, err := decodeRuntimeCompilerCgroup(string(group))
	if err != nil {
		t.Fatal(err)
	}
	cg := filepath.Join("/sys/fs/cgroup", cgroup)
	for key, want := range map[string]string{"memory.max": "1073741824\n", "memory.high": "1073741824\n", "memory.swap.max": "0\n", "pids.max": "512\n"} {
		value, err := os.ReadFile(filepath.Join(cg, key))
		if err != nil || string(value) != want {
			t.Fatal("actual new measured1GiB finite kernel policy changed", key, string(value), err)
		}
	}
	initialEventRaw, err := os.ReadFile(filepath.Join(cg, "memory.events"))
	initialEvents, parseErr := runtimePHPCompilerEventsForNativeTest(initialEventRaw)
	if err != nil || parseErr != nil || runtimePHPCompilerNoOOMForNativeTest(initialEvents, initialEvents) != nil {
		t.Fatal("fresh complete kernel memory events unavailable or earlier OOM", err, parseErr)
	}
	const fixture = "/run/panel-runtime-collection24amv"
	archive := filepath.Join(fixture, id+".tar.gz")
	f, err := os.OpenFile(archive, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil || !runtimeBuildPrivateFile(st) || st.Size() <= 0 || st.Size() > 64<<20 {
		f.Close()
		t.Fatal("official private archive identity changed", err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		t.Fatal("archive differs from the independent compiled source pin", err)
	}
	work := filepath.Join(fixture, "official-gc-work")
	if err := os.Mkdir(work, 0755); err != nil {
		t.Fatal("never reuse/replay an old extraction", err)
	}
	if err := extractSource(archive, work); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "php-"+r.Version)
	transforms, err := prepareRuntimePHPBuildSource(r, source)
	if err != nil || len(transforms) != 1 || transforms[0].InputSHA256 != spec.inputSHA || transforms[0].DataSHA256 != spec.dataSHA {
		t.Fatal("original source/database preparation changed", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	ctx, err = withRuntimePHPCompilerGC(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := runtimePHPCompilerGCPolicy(ctx)
	if err != nil || policy == nil || policy.CFLAGS != runtimePHPCompilerGCFlags {
		t.Fatal("actual source-bound GC context absent", err)
	}
	if _, err := RunCommand(ctx, "/usr/bin/chown", "-R", "panel-build:panel-build", work); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(fixture, "official-gc-build.log")
	flags := []string{"--prefix=" + r.Prefix(), "--with-config-file-path=" + r.Prefix() + "/etc", "--with-config-file-scan-dir=" + r.Prefix() + "/etc/conf.d", "--enable-fpm", "--disable-cgi", "--disable-phpdbg", "--without-pear", "--with-openssl", "--with-curl", "--with-zlib", "--enable-mbstring", "--enable-bcmath", "--enable-sockets", "--enable-pcntl", "--enable-exif", "--enable-ftp", "--with-mysqli=mysqlnd", "--with-pdo-mysql=mysqlnd", "--with-zip", "--enable-intl", "--enable-gd", "--with-jpeg", "--with-freetype"}
	if err := buildCommand(ctx, source, log, source+"/configure", flags...); err != nil {
		t.Fatal("fresh actual official configure failed", err)
	}
	if err := buildCommand(ctx, source, log, "/usr/bin/make", "-j1", "Zend/zend_execute.lo"); err != nil {
		t.Fatal("actual Zend -O2 compilation exceeded new measured1GiB or failed", err)
	}
	var objects []map[string]any
	for _, name := range []string{"Zend/zend_execute.o", "Zend/.libs/zend_execute.o"} {
		path := filepath.Join(source, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<20 {
			t.Fatal("native Zend object absent or excessive", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil || int64(len(raw)) != info.Size() {
			t.Fatal(err)
		}
		object, err := elf.NewFile(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		machine := elf.EM_AARCH64
		if runtime.GOARCH == "amd64" {
			machine = elf.EM_X86_64
		}
		if object.Type != elf.ET_REL || object.Machine != machine {
			t.Fatal("wrong actual native object type/architecture")
		}
		symbols, err := object.Symbols()
		if err != nil || len(symbols) > 100000 {
			t.Fatal("native Zend symbols unavailable/excessive", err)
		}
		found := map[string]bool{}
		for _, symbol := range symbols {
			if symbol.Name == "execute_ex" || symbol.Name == "zend_execute" {
				if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Size == 0 || int(symbol.Section) >= len(object.Sections) {
					t.Fatal("Zend execution function was not compiled")
				}
				found[symbol.Name] = true
			}
		}
		object.Close()
		if !found["execute_ex"] || !found["zend_execute"] {
			t.Fatal("original native Zend execution functions missing", found)
		}
		sum := sha256.Sum256(raw)
		objects = append(objects, map[string]any{"path": name, "bytes": len(raw), "sha256": hex.EncodeToString(sum[:]), "original_execution_functions_verified": true})
	}
	if len(objects) == 0 {
		t.Fatal("ordinary target produced no actual native object")
	}
	data, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(data), runtimePHPCompilerGCFlags) || !strings.Contains(string(data), "compiler-collection-v2 member_snapshots=0 ") {
		t.Fatal("original O2, fixed GC flags or complete collection absent", err)
	}
	if empty, err := compilerHasNoChildren(); err != nil || !empty {
		t.Fatal("actual compiler scope not fully reaped", err)
	}
	peakRaw, err := os.ReadFile(filepath.Join(cg, "memory.peak"))
	peak, parseErr := strconv.ParseUint(strings.TrimSpace(string(peakRaw)), 10, 64)
	if err != nil || parseErr != nil || peak == 0 || peak > 1<<30 {
		t.Fatal("actual full lifetime peak outside the finite private budget", string(peakRaw), err)
	}
	finalEventRaw, err := os.ReadFile(filepath.Join(cg, "memory.events"))
	finalEvents, eventErr := runtimePHPCompilerEventsForNativeTest(finalEventRaw)
	if err != nil || eventErr != nil || runtimePHPCompilerNoOOMForNativeTest(initialEvents, finalEvents) != nil {
		t.Fatal("actual OOM/reset/unknown counters despite native objects", err, eventErr, initialEvents, finalEvents)
	}
	statRaw, err := os.ReadFile(filepath.Join(cg, "memory.stat"))
	if err != nil || len(statRaw) == 0 || len(statRaw) > 65536 {
		t.Fatal("actual final memory footprint unavailable", err)
	}
	sum := sha256.Sum256(data)
	proof := map[string]any{"passed": true, "release": id, "source_archive_sha256": r.SHA256, "compiler_policy": policy, "build_transform": transforms[0], "native_Zend_objects": objects, "O2_all_extensions_preserved_and_private_measured1GiB_swap0": true, "live_installer768MiB_limit_changed": false, "actual_native_peak_bytes": peak, "full_original_memory_events_before": initialEvents, "full_original_memory_events_after": finalEvents, "actual_OOM_oom_kill_group_kill_all_zero": true, "memory_events_and_peak_not_reset_or_written": true, "max_boundary_reclaim_is_not_an_OOM": true, "final_memory_stat_diagnostic": string(statRaw), "compile_log_sha256": hex.EncodeToString(sum[:]), "all_owned_children_reaped": true, "original_failed_job_or_work_replayed": false, "runtime_built_or_installed": false, "all50_commercial": false}
	raw, err := json.MarshalIndent(proof, "", "  ")
	if err != nil || atomicWrite(filepath.Join(fixture, "official-gc-1g-proof.json"), raw, 0600) != nil {
		t.Fatal("could not retain the original native proof", err)
	}
}
