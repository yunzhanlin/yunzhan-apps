//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

func runtimePublisherStepsFixture() []core.Step {
	messages := []string{
		"核对固定版本目录，等待源码构建锁", "本次安装总时限 240 分钟；超时即失败，不发布未校验程序", "已从官方站点下载源码，并通过目录中固定的 SHA-256 校验",
		"已逐字节核对 fileinfo 原始数据库；仅使用审核过的低内存构建表示，保留原文件、全部扩展及优化参数", "以独立构建用户配置精确版本及固定模块",
		"已启用固定 GCC 低内存编译策略；保留 -O2 和全部扩展，安装单元硬限 1 GiB、零交换，启动前保留 512 MiB 主机余量",
		"开始源码编译（1 个并行任务）；完整构建日志保存在专用缓存目录", "编译完成，安装到暂存目录", core.RuntimePHPPublicationStep, "独立目录安装完成；精确版本与固定构建模块核对通过",
	}
	var steps []core.Step
	for _, message := range messages {
		steps = append(steps, core.Step{Time: core.Now(), Message: message})
	}
	return steps
}

func runtimePublisherELFFixture(arch string) []byte {
	b := make([]byte, 4096)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:18], 3)
	machine := uint16(62)
	if arch == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(b[18:20], machine)
	binary.LittleEndian.PutUint32(b[20:24], 1)
	binary.LittleEndian.PutUint16(b[52:54], 64)
	copy(b[64:], "private synthetic ELF metadata model; not a real PHP installation")
	return b
}

func TestRuntimePHPFPMVersionRequiresExactNativeSAPIAndToken(t *testing.T) {
	r, _ := runtimecatalog.Find("php-8.2.35")
	for _, raw := range []string{"PHP 8.2.35 (fpm-fcgi)", "PHP 8.2.35 (fpm-fcgi) (built: Oct 26 2026 00:00:00)\nCopyright (c) The PHP Group\nZend Engine v4.2.35\n"} {
		if !runtimePHPFPMVersionMatches(r, raw) {
			t.Fatal("actual version form refused", raw)
		}
	}
	for _, raw := range []string{"", "PHP 8.2.350 (fpm-fcgi)", "PHP 8.2.35 (cli)", "PHP 8.2.35 (fpm-fcgi)evil", "warning PHP 8.2.35 (fpm-fcgi)", "diagnostic\nPHP 8.2.35 (fpm-fcgi)", "PHP 8.3.36 (fpm-fcgi)", "PHP 8.2.35 (fpm-fcgi)\x00", "PHP 8.2.35 (fpm-fcgi)\r\n", "PHP 8.2.35 (fpm-fcgi)\na\nb\nc\nd", strings.Repeat("x", 4097)} {
		if runtimePHPFPMVersionMatches(r, raw) {
			t.Fatal("foreign/ambiguous FPM admitted", raw)
		}
	}
	copy := r
	copy.SHA256 = strings.Repeat("0", 64)
	if runtimePHPFPMVersionMatches(copy, "PHP 8.2.35 (fpm-fcgi)") {
		t.Fatal("unbound official release")
	}
}

func TestRuntimePHPArtifactELFRequiresExact64BitArchitecture(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		header := runtimePublisherELFFixture(arch)[:64]
		if !runtimePHPArtifactELF(header, arch) {
			t.Fatal(arch)
		}
		for _, offset := range []int{0, 1, 2, 3, 4, 5, 6, 16, 18, 20, 52} {
			copy := append([]byte(nil), header...)
			copy[offset] = 0
			if runtimePHPArtifactELF(copy, arch) {
				t.Fatal("changed ELF header admitted", arch, offset)
			}
		}
		other := "amd64"
		if arch == other {
			other = "arm64"
		}
		if runtimePHPArtifactELF(header, other) || runtimePHPArtifactELF(header[:63], arch) || runtimePHPArtifactELF(header, "x86_64") {
			t.Fatal("foreign/truncated ELF")
		}
	}
}

func runtimePublisherTreeFixture(t *testing.T) (string, string, InstallStatus, InstallStatus, RuntimeManifest) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Root-owned isolated publication component models required")
	}
	base := t.TempDir()
	prefix, records := filepath.Join(base, "program"), filepath.Join(base, "records")
	for _, p := range []string{prefix, filepath.Join(prefix, "bin"), filepath.Join(prefix, "sbin")} {
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(records, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(p string, b []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
		// Exact fixture permissions must not depend on the caller's umask.
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"bin/php", "sbin/php-fpm"} {
		write(filepath.Join(prefix, name), runtimePublisherELFFixture(runtime.GOARCH), 0755)
	}
	original := runtimeOOMStatusFixture(core.ID())
	publisher := InstallStatus{JobID: core.ID(), ReleaseID: original.ReleaseID, State: "succeeded", Steps: runtimePublisherStepsFixture()}
	r, _ := runtimecatalog.Find(original.ReleaseID)
	info, err := os.Lstat(prefix)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	seal, err := sealRuntimePHPPublicationTree(t.Context(), r, publisher.JobID, prefix, []programQueueSnapshot{{path: prefix, info: info}}, func(_ context.Context, name string, args ...string) (string, error) {
		calls++
		if name != filepath.Join(prefix, "sbin/php-fpm") || strings.Join(args, " ") != "-n -v" {
			t.Fatal("not fixed FPM version command")
		}
		return "PHP 8.2.35 (fpm-fcgi) (built: fixture)", nil
	})
	if err != nil || calls != 1 || seal == nil {
		t.Fatal(seal, err, calls)
	}
	for name, a := range seal.Artifacts {
		data, e := os.ReadFile(filepath.Join(prefix, name))
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(data)
		if a.Bytes != int64(len(data)) || a.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("seal not bound to actual bytes")
		}
	}
	manifest := RuntimeManifest{Release: r, Architecture: runtime.GOARCH, InstalledAt: core.Now(), Extensions: []string{}, Configure: []string{}, Publication: seal}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	write(filepath.Join(prefix, ".panel-runtime.json"), b, 0644)
	for _, st := range []InstallStatus{original, publisher} {
		b, _ := json.Marshal(st)
		write(filepath.Join(records, st.JobID+".json"), b, 0600)
	}
	return prefix, records, original, publisher, manifest
}

type runtimePHPModeFixture struct {
	os.FileInfo
	mode os.FileMode
}

func (f runtimePHPModeFixture) Mode() os.FileMode { return f.mode }

func TestRuntimePHPArtifactMetadataRejectsPrivilegeBitsEvenWhenSandboxForbidsCreatingThem(t *testing.T) {
	prefix, _, _, _, _ := runtimePublisherTreeFixture(t)
	info, err := os.Lstat(filepath.Join(prefix, "bin/php"))
	if err != nil || !runtimePHPArtifactFile(info, false) {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0755 | os.ModeSetuid, 0755 | os.ModeSetgid, 0755 | os.ModeSticky, 0755 | os.ModeSymlink, 0775, 0777, 0700, 0644} {
		if runtimePHPArtifactFile(runtimePHPModeFixture{info, mode}, false) {
			t.Fatal("unsafe executable metadata admitted", mode)
		}
	}
}

func TestRuntimePHPPublisherTreeRejectsUnsealedOrChangedAuthorityWithoutRepair(t *testing.T) {
	mutations := []string{"original", "missing-seal", "seal-format", "seal-source", "same-job", "unknown-job", "bad-job", "missing-artifact", "extra-artifact", "artifact-hash", "artifact-size", "release", "architecture", "manifest-unknown", "manifest-duplicate", "manifest-whitespace", "missing-cli", "missing-fpm", "cli-link", "cli-hardlink", "cli-owner", "cli-writable", "cli-fifo", "cli-empty", "cli-oversize", "cli-header", "cli-foreign-arch", "fpm-mode", "fpm-header", "manifest-link", "manifest-hardlink", "manifest-owner", "manifest-mode", "manifest-size", "manifest-fifo", "bin-link", "sbin-writable", "prefix-link", "prefix-writable", "publisher-failed", "publisher-running", "publisher-error", "publisher-extension", "publisher-release", "publisher-no-op", "publisher-steps", "publisher-whitespace", "publisher-duplicate", "publisher-link", "publisher-hardlink", "publisher-mode", "publisher-owner", "old-pending", "new-pending", "cancelled"}
	for _, mutation := range mutations {
		t.Run(mutation, func(t *testing.T) {
			prefix, records, original, publisher, manifest := runtimePublisherTreeFixture(t)
			cli, fpm, mfile, pfile := filepath.Join(prefix, "bin/php"), filepath.Join(prefix, "sbin/php-fpm"), filepath.Join(prefix, ".panel-runtime.json"), filepath.Join(records, publisher.JobID+".json")
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			write := func(p string, b []byte) { t.Helper(); check(os.WriteFile(p, b, 0600)) }
			link := func(p string) { t.Helper(); check(os.Rename(p, p+".original")); check(os.Symlink(p+".original", p)) }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			changedManifest, changedPublisher := false, false
			switch mutation {
			case "missing-seal":
				manifest.Publication = nil
				changedManifest = true
			case "seal-format":
				manifest.Publication.Format = 2
				changedManifest = true
			case "seal-source":
				manifest.Publication.SourceSHA256 = strings.Repeat("0", 64)
				changedManifest = true
			case "same-job":
				manifest.Publication.JobID = original.JobID
				changedManifest = true
			case "unknown-job":
				manifest.Publication.JobID = core.ID()
				changedManifest = true
			case "bad-job":
				manifest.Publication.JobID = "../" + publisher.JobID
				changedManifest = true
			case "missing-artifact":
				delete(manifest.Publication.Artifacts, "sbin/php-fpm")
				changedManifest = true
			case "extra-artifact":
				manifest.Publication.Artifacts["foreign/php"] = RuntimePHPArtifact{1, strings.Repeat("0", 64)}
				changedManifest = true
			case "artifact-hash", "artifact-size":
				a := manifest.Publication.Artifacts["bin/php"]
				if mutation == "artifact-hash" {
					a.SHA256 = strings.Repeat("0", 64)
				} else {
					a.Bytes++
				}
				manifest.Publication.Artifacts["bin/php"] = a
				changedManifest = true
			case "release":
				manifest.Release.Version = "8.2.350"
				changedManifest = true
			case "architecture":
				manifest.Architecture = "x86_64"
				changedManifest = true
			case "manifest-unknown":
				b, e := os.ReadFile(mfile)
				check(e)
				write(mfile, []byte(strings.TrimSuffix(string(b), "}")+`,"allow":true}`))
			case "manifest-duplicate":
				b, e := os.ReadFile(mfile)
				check(e)
				write(mfile, []byte(strings.Replace(string(b), `"format": 1`, `"format": 1, "format": 1`, 1)))
			case "manifest-whitespace":
				b, e := os.ReadFile(mfile)
				check(e)
				write(mfile, append(b, '\n'))
			case "missing-cli":
				check(os.Remove(cli))
			case "missing-fpm":
				check(os.Remove(fpm))
			case "cli-link":
				link(cli)
			case "cli-hardlink":
				check(os.Link(cli, cli+".alias"))
			case "cli-owner":
				check(os.Chown(cli, 65534, 65534))
			case "cli-writable":
				check(os.Chmod(cli, 0775))
			case "cli-fifo":
				check(os.Remove(cli))
				check(syscall.Mkfifo(cli, 0755))
			case "cli-empty":
				check(os.Truncate(cli, 0))
			case "cli-oversize":
				check(os.Truncate(cli, 256<<20+1))
			case "cli-header":
				b := runtimePublisherELFFixture(runtime.GOARCH)
				b[0] = 0
				write(cli, b)
			case "cli-foreign-arch":
				other := "amd64"
				if runtime.GOARCH == other {
					other = "arm64"
				}
				write(cli, runtimePublisherELFFixture(other))
			case "fpm-mode":
				check(os.Chmod(fpm, 0644))
			case "fpm-header":
				b := runtimePublisherELFFixture(runtime.GOARCH)
				b[0] = 0
				write(fpm, b)
			case "manifest-link":
				link(mfile)
			case "manifest-hardlink":
				check(os.Link(mfile, mfile+".alias"))
			case "manifest-owner":
				check(os.Chown(mfile, 65534, 65534))
			case "manifest-mode":
				check(os.Chmod(mfile, 0664))
			case "manifest-size":
				check(os.Truncate(mfile, 64<<10+1))
			case "manifest-fifo":
				check(os.Remove(mfile))
				check(syscall.Mkfifo(mfile, 0644))
			case "bin-link":
				link(filepath.Join(prefix, "bin"))
			case "sbin-writable":
				check(os.Chmod(filepath.Join(prefix, "sbin"), 0775))
			case "prefix-link":
				link(prefix)
			case "prefix-writable":
				check(os.Chmod(prefix, 0775))
			case "publisher-failed":
				publisher.State = "failed"
				changedPublisher = true
			case "publisher-running":
				publisher.State = "running"
				changedPublisher = true
			case "publisher-error":
				publisher.Error = "original failure"
				changedPublisher = true
			case "publisher-extension":
				publisher.ExtensionID = "redis"
				changedPublisher = true
			case "publisher-release":
				publisher.ReleaseID = "php-8.3.36"
				changedPublisher = true
			case "publisher-no-op":
				publisher.Steps = []core.Step{{Time: core.Now(), Message: "该精确版本已安装，清单、程序文件与实际程序精确版本核对通过；未重新安装"}}
				changedPublisher = true
			case "publisher-steps":
				publisher.Steps[0].Message += " "
				changedPublisher = true
			case "publisher-whitespace":
				b, e := os.ReadFile(pfile)
				check(e)
				write(pfile, append(b, '\n'))
			case "publisher-duplicate":
				b, e := os.ReadFile(pfile)
				check(e)
				write(pfile, []byte(strings.Replace(string(b), `"state":"succeeded"`, `"state":"succeeded","state":"succeeded"`, 1)))
			case "publisher-link":
				link(pfile)
			case "publisher-hardlink":
				check(os.Link(pfile, pfile+".alias"))
			case "publisher-mode":
				check(os.Chmod(pfile, 0644))
			case "publisher-owner":
				check(os.Chown(pfile, 65534, 65534))
			case "old-pending":
				check(os.Mkdir(prefix+".pending-"+original.JobID, 0755))
			case "new-pending":
				check(os.Mkdir(prefix+".pending-"+publisher.JobID, 0755))
			case "cancelled":
				cancel()
			}
			if changedManifest {
				b, e := json.MarshalIndent(manifest, "", "  ")
				check(e)
				write(mfile, b)
			}
			if changedPublisher {
				b, e := json.Marshal(publisher)
				check(e)
				write(pfile, b)
			}
			info, err := os.Lstat(prefix)
			check(err)
			root, err := os.OpenRoot(records)
			check(err)
			defer root.Close()
			before, err := os.ReadFile(filepath.Join(records, original.JobID+".json"))
			check(err)
			w, err := holdRuntimePHPPublisherTree(ctx, root, original, prefix, []programQueueSnapshot{{path: prefix, info: info}})
			if mutation == "original" {
				if err != nil || w == nil || !w.current() || w.evidence.PublisherJobID != publisher.JobID || w.evidence.Original.JobID != original.JobID {
					t.Fatal(w, err)
				}
			} else if err == nil || w != nil {
				if w != nil {
					w.close()
				}
				t.Fatal("unbound publisher or unsafe tree admitted", mutation)
			}
			if w != nil {
				w.close()
			}
			after, err := os.ReadFile(filepath.Join(records, original.JobID+".json"))
			check(err)
			if !bytes.Equal(before, after) {
				t.Fatal("original OOM ledger was repaired")
			}
		})
	}
}

func TestRuntimePHPPublisherHeldIdentityDetectsChangesAndProducerNeverAdopts(t *testing.T) {
	for _, mutation := range []string{"file-bytes", "file-replace-same-bytes", "file-owner", "manifest-bytes", "manifest-replace", "publisher-ledger", "publisher-replace", "old-pending", "new-pending", "prefix-replace", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			prefix, records, original, publisher, manifest := runtimePublisherTreeFixture(t)
			root, err := os.OpenRoot(records)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			info, _ := os.Lstat(prefix)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			w, err := holdRuntimePHPPublisherTree(ctx, root, original, prefix, []programQueueSnapshot{{path: prefix, info: info}})
			if err != nil {
				t.Fatal(err)
			}
			defer w.close()
			check := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			file := filepath.Join(prefix, "bin/php")
			switch mutation {
			case "file-bytes":
				f, e := os.OpenFile(file, os.O_WRONLY, 0)
				check(e)
				_, e = f.WriteAt([]byte("changed"), 100)
				check(e)
				f.Close()
			case "file-replace-same-bytes", "manifest-replace", "publisher-replace":
				if mutation == "manifest-replace" {
					file = filepath.Join(prefix, ".panel-runtime.json")
				}
				if mutation == "publisher-replace" {
					file = filepath.Join(records, publisher.JobID+".json")
				}
				b, e := os.ReadFile(file)
				check(e)
				st, e := os.Stat(file)
				check(e)
				check(os.WriteFile(file+".replacement", b, st.Mode()))
				check(os.Rename(file+".replacement", file))
			case "file-owner":
				check(os.Chown(file, 65534, 65534))
			case "manifest-bytes":
				check(os.WriteFile(filepath.Join(prefix, ".panel-runtime.json"), []byte("{}"), 0644))
			case "publisher-ledger":
				check(os.WriteFile(filepath.Join(records, publisher.JobID+".json"), []byte("{}"), 0600))
			case "old-pending":
				check(os.Mkdir(prefix+".pending-"+original.JobID, 0755))
			case "new-pending":
				check(os.Mkdir(prefix+".pending-"+publisher.JobID, 0755))
			case "prefix-replace":
				check(os.Rename(prefix, prefix+".original"))
				check(os.Mkdir(prefix, 0755))
			case "cancelled":
				cancel()
			}
			if w.final() {
				t.Fatal("stale held publisher identity admitted", mutation)
			}
			called := false
			seal, err := sealRuntimePHPPublication(t.Context(), manifest.Release, publisher.JobID, prefix, func(context.Context, string, ...string) (string, error) {
				called = true
				return "", errors.New("must not execute")
			})
			if seal != nil || err == nil || called {
				t.Fatal("producer adopted arbitrary existing prefix")
			}
		})
	}
}
