//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestRuntimeSupersededCompileOOMProofKeepsOldFailureAndIndependentLeases(t *testing.T) {
	mutations := []string{"original", "missing-start", "start-link", "start-hardlink", "start-mode", "start-nonempty", "busy-start", "missing-build", "build-link", "build-hardlink", "build-mode", "build-nonempty", "busy-build", "old-missing", "old-link", "old-hardlink", "old-mode", "old-owner", "old-failed", "old-success", "old-queued", "old-error", "old-release", "old-extension", "old-phase", "old-duplicate", "old-whitespace", "missing-unit", "active-unit", "changed-unit", "missing-core", "bad-core", "changed-core", "publisher-error", "publisher-nil", "publisher-same-job", "publisher-original-id", "publisher-original-steps", "publisher-no-binding", "publisher-stale", "mid-old-replace", "mid-old-change", "mid-start", "mid-build", "mid-publisher", "mid-elf", "mid-root", "cancelled"}
	for _, mutation := range mutations {
		t.Run(mutation, func(t *testing.T) {
			prefix, records, original, _, _ := runtimePublisherTreeFixture(t)
			build := filepath.Join(filepath.Dir(records), "build")
			if err := os.Mkdir(build, 0700); err != nil {
				t.Fatal(err)
			}
			oldFile, start, buildFile := filepath.Join(records, original.JobID+".json"), filepath.Join(records, ".native-start.lock"), filepath.Join(build, "build.lock")
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			write := func(p string, b []byte) { t.Helper(); check(os.WriteFile(p, b, 0600)) }
			write(start, nil)
			write(buildFile, nil)
			showCalls, coreCalls := 0, 0
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			p := runtimeSupersededCompileOOMProof{
				open: func() (*os.Root, error) { return os.OpenRoot(records) },
				current: func(root *os.Root) bool {
					a, e := os.Lstat(records)
					b, e2 := root.Stat(".")
					return e == nil && e2 == nil && runtimeInstallPrivateDirectory(a) && runtimeInstallPrivateDirectory(b) && os.SameFile(a, b)
				},
				fence: func() (func() bool, func(), error) {
					root, e := os.OpenRoot(build)
					if e != nil {
						return nil, nil, e
					}
					f, info, e := runtimeCompileOOMReadLease(root, "build.lock")
					if e != nil {
						root.Close()
						return nil, nil, e
					}
					return func() bool { return runtimeCompileOOMLeaseCurrent(root, "build.lock", f, info) }, func() { f.Close(); root.Close() }, nil
				},
				stopped: func() (string, error) {
					showCalls++
					if mutation == "missing-unit" {
						return "", errors.New("missing original unit")
					}
					if mutation == "active-unit" {
						return strings.Replace(runtimeOOMStoppedFixture, "MainPID=0", "MainPID=42", 1), nil
					}
					if mutation == "changed-unit" && showCalls == 2 {
						return strings.Replace(runtimeOOMStoppedFixture, "ExecMainPID=1234", "ExecMainPID=1235", 1), nil
					}
					return runtimeOOMStoppedFixture, nil
				},
				publisher: func(ctx context.Context, root *os.Root, st InstallStatus) (*runtimePHPPublisherWitness, error) {
					if mutation == "publisher-error" {
						return nil, errors.New("publisher not bound")
					}
					if mutation == "publisher-nil" {
						return nil, nil
					}
					info, e := os.Lstat(prefix)
					if e != nil {
						return nil, e
					}
					w, e := holdRuntimePHPPublisherTree(ctx, root, st, prefix, []programQueueSnapshot{{path: prefix, info: info}})
					if e != nil {
						return nil, e
					}
					switch mutation {
					case "publisher-same-job":
						w.evidence.PublisherJobID = original.JobID
					case "publisher-original-id":
						w.evidence.Original.JobID = core.ID()
					case "publisher-original-steps":
						w.evidence.Original.Steps = append([]core.Step(nil), w.evidence.Original.Steps...)
						w.evidence.Original.Steps[0].Message += " "
					case "publisher-no-binding":
						w.binding = "unbound"
					case "publisher-stale":
						w.current = func() bool { return false }
					}
					return w, nil
				},
				validate: func(_ context.Context, in core.RuntimeSupersededCompileOOMEvidence) (string, error) {
					coreCalls++
					if !reflect.DeepEqual(in.Original, core.RuntimeCompileOOMInstallEvidence{JobID: original.JobID, ReleaseID: original.ReleaseID, Steps: original.Steps}) || mutation == "missing-core" {
						return "", errors.New("original Core not bound")
					}
					if mutation == "bad-core" {
						return "unbound", nil
					}
					if mutation == "changed-core" && coreCalls == 2 {
						return core.Hash("changed publisher Core"), nil
					}
					return core.Hash("independent original failure and succeeded publisher"), nil
				},
			}
			path := oldFile
			if strings.Contains(mutation, "start") {
				path = start
			}
			if strings.Contains(mutation, "build") {
				path = buildFile
			}
			switch mutation {
			case "missing-start", "missing-build", "old-missing":
				check(os.Remove(path))
			case "start-link", "build-link", "old-link":
				check(os.Rename(path, path+".original"))
				check(os.Symlink(path+".original", path))
			case "start-hardlink", "build-hardlink", "old-hardlink":
				check(os.Link(path, path+".alias"))
			case "start-mode", "build-mode", "old-mode":
				check(os.Chmod(path, 0644))
			case "start-nonempty", "build-nonempty":
				write(path, []byte("original nonempty lock retained"))
			case "busy-start", "busy-build":
				f, e := os.OpenFile(path, os.O_RDWR, 0)
				check(e)
				defer f.Close()
				check(unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB))
			case "old-owner":
				check(os.Chown(path, 65534, 65534))
			case "old-failed", "old-success", "old-queued", "old-error", "old-release", "old-extension", "old-phase":
				st := original
				st.Steps = append([]core.Step(nil), st.Steps...)
				switch mutation {
				case "old-failed":
					st.State, st.Error = "failed", core.RuntimeCompileOOMError
				case "old-success":
					st.State = "succeeded"
				case "old-queued":
					st.State = "queued"
				case "old-error":
					st.Error = core.RuntimeCompileOOMError
				case "old-release":
					st.ReleaseID = "php-8.2.33"
				case "old-extension":
					st.ExtensionID = "redis"
				case "old-phase":
					st.Steps[len(st.Steps)-1].Message = "编译完成，安装到暂存目录"
				}
				b, e := json.Marshal(st)
				check(e)
				write(oldFile, b)
			case "old-duplicate":
				b, e := os.ReadFile(oldFile)
				check(e)
				write(oldFile, []byte(strings.Replace(string(b), `"state":"running"`, `"state":"running","state":"running"`, 1)))
			case "old-whitespace":
				b, e := os.ReadFile(oldFile)
				check(e)
				write(oldFile, append(b, '\n'))
			case "mid-old-replace", "mid-old-change", "mid-start", "mid-build", "mid-publisher", "mid-elf", "mid-root", "cancelled":
				p.checkpoint = func() error {
					switch mutation {
					case "mid-old-replace", "mid-start", "mid-build":
						path := oldFile
						if mutation == "mid-start" {
							path = start
						}
						if mutation == "mid-build" {
							path = buildFile
						}
						b, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						if e = os.WriteFile(path+".replacement", b, 0600); e != nil {
							return e
						}
						return os.Rename(path+".replacement", path)
					case "mid-old-change":
						return os.WriteFile(oldFile, []byte("{}"), 0600)
					case "mid-publisher":
						entries, e := os.ReadDir(records)
						if e != nil {
							return e
						}
						for _, entry := range entries {
							if strings.HasSuffix(entry.Name(), ".json") && entry.Name() != original.JobID+".json" {
								return os.WriteFile(filepath.Join(records, entry.Name()), []byte("{}"), 0600)
							}
						}
						return errors.New("missing publisher fixture")
					case "mid-elf":
						f, err := os.OpenFile(filepath.Join(prefix, "bin/php"), os.O_WRONLY, 0)
						if err != nil {
							return err
						}
						_, err = f.WriteAt([]byte("changed same-size original model"), 100)
						f.Close()
						return err
					case "mid-root":
						if e := os.Rename(records, records+".original"); e != nil {
							return e
						}
						return os.Mkdir(records, 0700)
					case "cancelled":
						cancel()
					}
					return nil
				}
			}
			before, beforeErr := os.ReadFile(oldFile)
			err := p.check(ctx, original.JobID)
			if mutation == "original" {
				if err != nil || showCalls != 2 || coreCalls != 2 {
					t.Fatal(err, showCalls, coreCalls)
				}
			} else if err == nil {
				t.Fatal("uncertain or changed successor proof admitted", mutation)
			}
			if !strings.HasPrefix(mutation, "mid-") {
				after, afterErr := os.ReadFile(oldFile)
				if (beforeErr == nil) != (afterErr == nil) || !reflect.DeepEqual(before, after) {
					t.Fatal("proof rewrote original old failure evidence")
				}
			}
		})
	}
}
