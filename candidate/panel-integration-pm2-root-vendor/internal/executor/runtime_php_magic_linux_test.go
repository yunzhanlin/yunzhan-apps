//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/runtimecatalog"
)

// Negative filesystem models use sparse, hash-INVALID source files. They do
// not impersonate a genuine source or a native compilation; the opt-in native
// test separately exercises both exact official files and emitted ELF bytes.
func TestRuntimeMagicPreparationRejectsUnsafeOrUnreviewedSourcesWithoutRepair(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root-owned extraction authority required")
	}
	for _, mutation := range []string{"wrong-release", "wrong-archive", "relative", "wrong-source-name", "source-link", "ext-link", "fileinfo-link", "source-writable", "ext-writable", "fileinfo-owner", "source-file-link", "source-file-hardlink", "source-file-owner", "source-file-group", "source-file-mode", "source-file-fifo", "source-file-size", "source-hash"} {
		t.Run(mutation, func(t *testing.T) {
			r, _ := runtimecatalog.Find("php-8.2.35")
			spec, _ := runtimeMagicSpecification(r.ID)
			base := t.TempDir()
			source := filepath.Join(base, "php-8.2.35")
			for _, path := range []string{source, filepath.Join(source, "ext"), filepath.Join(source, "ext/fileinfo")} {
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			file := filepath.Join(source, runtimeMagicPath)
			f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(int64(spec.rawBytes)); err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "wrong-release":
				r.Family = "nginx"
			case "wrong-archive":
				r.SHA256 = strings.Repeat("0", 64)
			case "relative":
				source = "php-8.2.35"
			case "wrong-source-name":
				check(os.Rename(source, source+"-unknown"))
				source += "-unknown"
				file = filepath.Join(source, runtimeMagicPath)
			case "source-link", "ext-link", "fileinfo-link":
				target := source
				if mutation == "ext-link" {
					target = filepath.Join(source, "ext")
				} else if mutation == "fileinfo-link" {
					target = filepath.Join(source, "ext/fileinfo")
				}
				check(os.Rename(target, target+".original"))
				check(os.Symlink(target+".original", target))
			case "source-writable":
				check(os.Chmod(source, 0777))
			case "ext-writable":
				check(os.Chmod(filepath.Join(source, "ext"), 0775))
			case "fileinfo-owner":
				check(os.Chown(filepath.Join(source, "ext/fileinfo"), 65534, 65534))
				defer os.Chown(filepath.Join(source, "ext/fileinfo"), 0, 0)
			case "source-file-link":
				check(os.Rename(file, file+".original"))
				check(os.Symlink(file+".original", file))
			case "source-file-hardlink":
				check(os.Link(file, file+".alias"))
			case "source-file-owner":
				check(os.Chown(file, 65534, 0))
			case "source-file-group":
				check(os.Chown(file, 0, 65534))
			case "source-file-mode":
				check(os.Chmod(file, 0600))
			case "source-file-fifo":
				check(os.Remove(file))
				check(syscall.Mkfifo(file, 0644))
			case "source-file-size":
				check(os.Truncate(file, int64(spec.rawBytes)-1))
			}
			before, err := os.Lstat(file)
			if err != nil {
				t.Fatal(err)
			}
			out, err := prepareRuntimePHPBuildSource(r, source)
			if err == nil || out != nil {
				t.Fatal("unsafe/unknown source was changed or admitted", mutation, out, err)
			}
			after, err := os.Lstat(file)
			if err != nil || !programQueueSame(before, after) {
				t.Fatal("rejected original input identity changed", mutation, err)
			}
			if mutation != "relative" {
				entries, err := os.ReadDir(filepath.Join(source, "ext/fileinfo"))
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".data_file.c-build-") || strings.HasPrefix(entry.Name(), "data_file.c.upstream-") {
						t.Fatal("rejected source left compatibility output", entry.Name())
					}
				}
			}
		})
	}
}
