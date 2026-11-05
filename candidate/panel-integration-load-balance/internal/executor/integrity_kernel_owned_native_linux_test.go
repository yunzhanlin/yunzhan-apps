//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// This explicitly opted-in test uses only newly owned temporary sites and
// actual kernel ioctls. Its internal authority callback isolates filesystem
// behavior; it is not a substitute for signed-install/current-actor/GUI tests.
func TestIntegrityKernelOwnedNativeRoundTrip(t *testing.T) {
	if os.Getenv("PANEL_INTEGRITY_KERNEL_NATIVE") != "1" {
		t.Skip("explicit owned native inode fixture required")
	}
	if os.Geteuid() != 0 || !integrityKernelHasCapability() {
		t.Fatal("explicit native fixture requires actual CAP_LINUX_IMMUTABLE")
	}
	for _, scenario := range []string{"complete-with-held-writer-and-exclusion", "interrupted-needs-fresh-release"} {
		t.Run(scenario, func(t *testing.T) {
			s, site, _ := appReliabilityFixture(t)
			publicPath := filepath.Join(s.Config.SitesDir, site, "public")
			if err := os.Chown(publicPath, 33, 33); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(publicPath, 0755); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{"code", "uploads"} {
				p := filepath.Join(publicPath, dir)
				if err := os.Mkdir(p, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(p, 33, 33); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"data.txt", "code/static.txt", "preexisting.txt", "uploads/dynamic.txt"} {
				p := filepath.Join(publicPath, name)
				if err := os.WriteFile(p, bytes.Repeat([]byte("A"), 4096), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(p, 33, 33); err != nil {
					t.Fatal(err)
				}
			}
			files, _, err := s.openIntegrityWatchFiles(site)
			if err != nil {
				t.Fatal(err)
			}
			defer files.Close()
			public, err := files.public.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer public.Close()
			preexisting, err := openIntegrityFlagTarget(public, "preexisting.txt", false)
			if err != nil {
				t.Fatal(err)
			}
			originalPreexisting, err := readIntegrityInodeFlags(preexisting, false)
			if err != nil {
				preexisting.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				current, e := readIntegrityInodeFlags(preexisting, false)
				if e != nil {
					t.Error(e)
				} else if current.Flags != originalPreexisting.Flags {
					if e = unix.IoctlSetPointerInt(int(preexisting.Fd()), unix.FS_IOC_SETFLAGS, originalPreexisting.Flags); e != nil {
						t.Error("new owned pre-existing fixture flag restoration failed", e)
					}
				}
				preexisting.Close()
			})
			if _, err = setIntegrityInodeImmutable(preexisting, false, originalPreexisting, true); err != nil {
				t.Fatal(err)
			}
			var child *exec.Cmd
			var childInput io.WriteCloser
			var childOutput *bufio.Reader
			var childErrors bytes.Buffer
			if scenario == "complete-with-held-writer-and-exclusion" {
				held, e := os.OpenFile(filepath.Join(publicPath, "data.txt"), os.O_RDWR, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer held.Close()
				outsidePath := filepath.Join(s.Config.SitesDir, "owned-outside-"+core.ID())
				if e = os.Mkdir(outsidePath, 0700); e != nil {
					t.Fatal(e)
				}
				if e = os.Chown(outsidePath, 33, 33); e != nil {
					t.Fatal(e)
				}
				outside, e := os.Open(outsidePath)
				if e != nil {
					t.Fatal(e)
				}
				defer outside.Close()
				const sample = `import errno,json,os,sys
assert os.geteuid()==os.getegid()==33
os.pwrite(4,b'A',0);os.fsync(4)
os.ftruncate(4,4096)
fd=os.open('data.txt',os.O_WRONLY,dir_fd=3);os.close(fd)
os.rename('data.txt','positive-control-moved',src_dir_fd=3,dst_dir_fd=3);os.rename('positive-control-moved','data.txt',src_dir_fd=3,dst_dir_fd=3)
os.link('data.txt','positive-control-alias',src_dir_fd=3,dst_dir_fd=5,follow_symlinks=False);os.unlink('positive-control-alias',dir_fd=5)
fd=os.open('control',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=3);os.close(fd);os.unlink('control',dir_fd=3)
print(json.dumps({'ready':True,'uid':os.geteuid()}),flush=True)
assert sys.stdin.readline().strip()=='protected'
results={}
for name in ['held-write','truncate','new-open','new-entry','rename','unlink','outside-hardlink']:
 try:
  if name=='held-write':os.pwrite(4,b'B',0)
  elif name=='truncate':os.ftruncate(4,1)
  elif name=='new-open':fd=os.open('data.txt',os.O_WRONLY,dir_fd=3);os.close(fd)
  elif name=='new-entry':fd=os.open('new',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=3);os.close(fd)
  elif name=='rename':os.rename('data.txt','moved',src_dir_fd=3,dst_dir_fd=3)
  elif name=='unlink':os.unlink('data.txt',dir_fd=3)
  elif name=='outside-hardlink':os.link('data.txt','alias',src_dir_fd=3,dst_dir_fd=5,follow_symlinks=False)
  results[name]=0
 except OSError as e:results[name]=e.errno
fd=os.open('uploads/dynamic.txt',os.O_WRONLY,dir_fd=3);os.write(fd,b'B');os.fsync(fd);os.close(fd)
print(json.dumps({'blocked':results,'excluded_write':True}),flush=True)
assert sys.stdin.readline().strip()=='released'
os.pwrite(4,b'B',0);os.fsync(4)
os.mkdir('legitimate-after-release',0o700,dir_fd=3)
print(json.dumps({'original_held_writer_resumed':True,'legitimate_directory_created':True}),flush=True)
`
				child = exec.CommandContext(t.Context(), "/usr/bin/python3", "-I", "-B", "-c", sample)
				child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 33, Gid: 33, Groups: []uint32{}}}
				child.ExtraFiles = []*os.File{public, held, outside}
				child.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
				child.Stderr = &childErrors
				childInput, e = child.StdinPipe()
				if e != nil {
					t.Fatal(e)
				}
				stdout, e := child.StdoutPipe()
				if e != nil {
					t.Fatal(e)
				}
				childOutput = bufio.NewReader(stdout)
				if e = child.Start(); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() {
					childInput.Close()
					if child.ProcessState == nil {
						child.Process.Kill()
						child.Wait()
					}
				})
				line, e := childOutput.ReadString('\n')
				if e != nil || !strings.Contains(line, `"ready": true`) {
					t.Fatal("actual UID33 positive control failed", line, e, childErrors.String())
				}
			}
			if _, err = s.moduleIntegrity(context.Background(), integrityKernelModule, "baseline", core.AppModuleInput{SiteID: site, Excludes: []string{"uploads"}}); err != nil {
				t.Fatal(err)
			}
			baseline, err := s.readIntegrityBaseline(integrityKernelModule, site)
			if err != nil {
				t.Fatal(err)
			}
			request := core.IntegrityKernelRequest{Format: 1, ID: core.ID(), ActorID: core.ID(), AccessRevision: 1, AppSHA: strings.Repeat("a", 64), Action: "enable", CreatedAt: core.Now(), Input: core.IntegrityKernelInput{SiteID: site, ExpectedAppVersion: core.IntegrityKernelAppVersion, BaselineSHA: baseline.Signature, Confirm: "PROTECT SITE " + site}}
			plan, err := s.integrityKernelPrepare(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range plan.Targets {
				fd, e := openIntegrityFlagTarget(public, target.Path, target.Directory)
				if e != nil {
					t.Fatal(e)
				}
				desired := target.Original.Flags
				t.Cleanup(func() {
					current, e := readIntegrityInodeFlags(fd, target.Directory)
					if e != nil {
						t.Error(e)
					} else if current.Flags != desired {
						if e = unix.IoctlSetPointerInt(int(fd.Fd()), unix.FS_IOC_SETFLAGS, desired); e != nil {
							t.Error("owned fixture flags not restored", e)
						}
					}
					fd.Close()
				})
			}
			d, err := s.integrityKernelStore(true)
			if err != nil {
				t.Fatal(err)
			}
			if err = d.Mkdir(request.ID, 0700); err != nil {
				d.Close()
				t.Fatal(err)
			}
			d, err = integrityKernelChild(d, request.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if err = integrityKernelCreate(d, "request.json", request); err != nil {
				t.Fatal(err)
			}
			journal := integrityKernelFixtureStart(t, d, request, plan)
			calls, completed, attempted := 0, 0, false
			authority := func() error {
				calls++
				if scenario == "interrupted-needs-fresh-release" && calls == 5 {
					return errors.New("owned fixture: current authority stopped before next mutation")
				}
				return nil
			}
			err = s.integrityKernelApply(context.Background(), request, plan, journal, &completed, &attempted, authority)
			if scenario == "complete-with-held-writer-and-exclusion" && err != nil || scenario == "interrupted-needs-fresh-release" && err == nil || !attempted {
				t.Fatal("actual enable boundary", scenario, completed, attempted, err)
			}
			if scenario == "complete-with-held-writer-and-exclusion" {
				if _, err = io.WriteString(childInput, "protected\n"); err != nil {
					t.Fatal(err)
				}
				line, e := childOutput.ReadString('\n')
				if e != nil {
					t.Fatal(e, childErrors.String())
				}
				var result struct {
					Blocked  map[string]int `json:"blocked"`
					Excluded bool           `json:"excluded_write"`
				}
				if json.Unmarshal([]byte(line), &result) != nil || len(result.Blocked) != 7 || !result.Excluded {
					t.Fatal(line)
				}
				for kind, number := range result.Blocked {
					if number != int(unix.EPERM) {
						t.Fatal("original UID33 operation was not blocked", kind, number)
					}
				}
				if data, e := os.ReadFile(filepath.Join(publicPath, "data.txt")); e != nil || !bytes.Equal(data, bytes.Repeat([]byte("A"), 4096)) {
					t.Fatal("held writer changed original protected bytes", e)
				}
				t.Logf("actual_uid33_protection=%s", strings.TrimSpace(line))
			}
			before, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
			if err != nil {
				t.Fatal(err)
			}
			out := core.IntegrityKernelOperation{Request: request, RequestSHA: core.IntegrityKernelRequestSHA(request), Revision: 1, State: "succeeded", PlanSHA: integrityKernelDigest(plan), EnableOperation: request.ID, Completed: completed, FinishedAt: core.Now()}
			for _, target := range plan.Targets {
				if target.Directory {
					out.Directories++
				} else {
					out.Files++
				}
			}
			if scenario == "interrupted-needs-fresh-release" {
				out.State = "needs-attention"
				out.Error = "original owned native transition stopped; never replay"
			}
			if err = integrityKernelCreate(d, "result.json", out); err != nil {
				t.Fatal(err)
			}
			makeRelease := func(previous core.IntegrityKernelRequest, revision int64) (core.IntegrityKernelRequest, *modulePrivateDirectory, *integrityKernelJournal) {
				t.Helper()
				r := request
				r.ID = core.ID()
				r.Action = "release"
				r.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
				r.Input.ExpectedRevision = revision
				r.Input.BaselineSHA = ""
				r.Input.SourceOperation = previous.ID
				r.Input.SourceSHA = core.IntegrityKernelRequestSHA(previous)
				r.Input.Confirm = "RELEASE SITE " + site
				root, e := s.integrityKernelStore(true)
				if e != nil {
					t.Fatal(e)
				}
				if e = root.Mkdir(r.ID, 0700); e != nil {
					root.Close()
					t.Fatal(e)
				}
				root, e = integrityKernelChild(root, r.ID)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { root.Close() })
				if e = integrityKernelCreate(root, "request.json", r); e != nil {
					t.Fatal(e)
				}
				j := integrityKernelFixtureStart(t, root, r, plan)
				return r, root, j
			}
			release, _, releaseJournal := makeRelease(request, 1)
			released, releaseAttempted := 0, false
			if err = s.integrityKernelRelease(context.Background(), release, plan, releaseJournal, &released, &releaseAttempted, func() error { return nil }); err != nil || released != len(plan.Targets) || !releaseAttempted {
				t.Fatal("fresh original-plan release failed", released, releaseAttempted, err)
			}
			for _, target := range plan.Targets {
				f, e := openIntegrityFlagTarget(public, target.Path, target.Directory)
				if e != nil {
					t.Fatal(e)
				}
				state, e := readIntegrityInodeFlags(f, target.Directory)
				f.Close()
				if e != nil || state.Flags != target.Original.Flags {
					t.Fatal("original inode flags were not preserved", target.Path, state.Flags, target.Original.Flags, e)
				}
			}
			if scenario == "complete-with-held-writer-and-exclusion" {
				if _, err = io.WriteString(childInput, "released\n"); err != nil {
					t.Fatal(err)
				}
				line, e := childOutput.ReadString('\n')
				if e != nil || !strings.Contains(line, `"original_held_writer_resumed": true`) {
					t.Fatal("original writer did not resume", line, e, childErrors.String())
				}
				if e = child.Wait(); e != nil {
					t.Fatal(e, childErrors.String())
				}
				// A fresh recovery identity observes already-cleared own flags and
				// legitimate subsequent writes; it does not replay original enable.
				recovery, _, recoveryJournal := makeRelease(release, 2)
				count, changed := 0, false
				if e = s.integrityKernelRelease(context.Background(), recovery, plan, recoveryJournal, &count, &changed, func() error { return nil }); e != nil || count != len(plan.Targets) || changed {
					t.Fatal("already-released original recovery failed or repeated ioctls", count, changed, e)
				}
			}
			after, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
			if err != nil || string(after) != string(before) {
				t.Fatal("fresh release rewrote original enable journal", err)
			}
			current, err := readIntegrityInodeFlags(preexisting, false)
			if err != nil || current.Flags != originalPreexisting.Flags|integrityImmutableFlag {
				t.Fatal("application removed pre-existing protection", current, err)
			}
		})
	}
}
