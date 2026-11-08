//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestRuntimeBuildNativeRootCacheRetainsWorkAndRejectsForeignPaths(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_CACHE_NATIVE") != "1" {
		t.Skip("explicit private Root cache / real unprivileged compiler fixture required")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("runtime cache supervisor identity changed", identity)
	}
	builder, err := user.Lookup("panel-build")
	if err != nil || builder.Uid == "0" {
		t.Fatal("actual nonprivileged builder missing", err)
	}
	uid, err := strconv.Atoi(builder.Uid)
	if err != nil {
		t.Fatal(err)
	}
	const fixture = "/run/panel-runtime-cache24amp"
	id := core.ID()
	base, err := prepareRuntimeBuildDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	work, err := prepareRuntimeBuildWork(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(work, uid, -1); err != nil {
		t.Fatal(err)
	}
	probe := `import json,os,pathlib,stat
work=pathlib.Path.cwd(); base=work.parent; cache=base.parent
identity={}
for line in pathlib.Path('/proc/self/status').read_text().splitlines():
 if line.startswith(('Uid:','CapInh:','CapPrm:','CapEff:','CapAmb:','NoNewPrivs:')):
  key,value=line.split(':',1);identity[key]=value.strip()
assert os.geteuid()!=0 and all(identity[k]=='0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapAmb')) and identity['NoNewPrivs']=='1'
denied=[]
for action in ('replace-job','create-sibling','replace-source','create-cache-link'):
 try:
  if action=='replace-job': base.rename(cache/(base.name+'-replaced'))
  elif action=='create-sibling': (cache/'untrusted-sibling').mkdir()
  elif action=='replace-source': (base/'source.tar.gz').write_bytes(b'untrusted')
  else: (cache/'untrusted-link').symlink_to('/etc/panel')
 except PermissionError: denied.append(action)
 else: raise AssertionError(action+' unexpectedly writable')
(work/'compiler-owned-proof.json').write_text(json.dumps({'passed':True,'denied':denied,'identity':identity},sort_keys=True))
`
	marker := filepath.Join(base, "source.tar.gz")
	if err := os.WriteFile(marker, []byte("root-source-authority"), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(base, "build.log")
	if err := buildCommand(context.Background(), work, logPath, "/usr/bin/python3", "-c", probe); err != nil {
		t.Fatal("actual builder cache boundary", err)
	}
	data, err := os.ReadFile(filepath.Join(work, "compiler-owned-proof.json"))
	var child map[string]any
	if err != nil || json.Unmarshal(data, &child) != nil || child["passed"] != true {
		t.Fatal("actual compiler proof missing", err)
	}
	old, err := os.Lstat(work)
	if err != nil {
		t.Fatal(err)
	}
	newWork, err := prepareRuntimeBuildWork(base)
	if err != nil || newWork != work {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	retained := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "retained-work-") {
			retained = filepath.Join(base, entry.Name())
		}
	}
	info, err := os.Lstat(retained)
	if err != nil || !os.SameFile(old, info) || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
		t.Fatal("prior work removed, replaced or re-owned", err)
	}
	historical, err := os.ReadFile(filepath.Join(retained, "compiler-owned-proof.json"))
	if err != nil || string(historical) != string(data) {
		t.Fatal("prior work bytes changed", err)
	}
	newInfo, err := os.Lstat(work)
	if err != nil || newInfo.Sys().(*syscall.Stat_t).Uid != 0 || os.SameFile(old, newInfo) {
		t.Fatal("retry reused old compiler-owned directory", err)
	}
	if value, err := os.ReadFile(marker); err != nil || string(value) != "root-source-authority" {
		t.Fatal("compiler altered source authority", err)
	}
	for _, kind := range []string{"symlink", "foreign-owner", "foreign-group", "writable", "private-mode", "regular-file"} {
		id := core.ID()
		path := filepath.Join(runtimeBuildCache, id)
		if kind == "regular-file" {
			if err := os.WriteFile(path, []byte("retain foreign file"), 0600); err != nil {
				t.Fatal(err)
			}
		} else if kind == "symlink" {
			if err := os.Symlink(base, path); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Mkdir(path, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
			if kind == "foreign-owner" {
				if err := os.Chown(path, uid, -1); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "foreign-group" {
				if err := os.Chown(path, 0, 33); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "writable" {
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "private-mode" {
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
		}
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prepareRuntimeBuildDirectory(id); err == nil {
			t.Fatal("foreign job path accepted", kind)
		}
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Sys().(*syscall.Stat_t).Uid != after.Sys().(*syscall.Stat_t).Uid || before.Sys().(*syscall.Stat_t).Gid != after.Sys().(*syscall.Stat_t).Gid {
			t.Fatal("foreign job path repaired", kind, err)
		}
	}
	// A compiler-owned work link is not deleted or followed on retry.
	linkBase, err := prepareRuntimeBuildDirectory(core.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(retained, filepath.Join(linkBase, "work")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRuntimeBuildWork(linkBase); err == nil {
		t.Fatal("work symlink accepted")
	}
	if link, err := os.Readlink(filepath.Join(linkBase, "work")); err != nil || link != retained {
		t.Fatal("work symlink removed or repaired", err)
	}
	proof, _ := json.MarshalIndent(map[string]any{"passed": true, "actual_build_command_executed": true, "actual_unprivileged_child": child, "root_managed_cache": runtimeBuildCache, "job_id": id, "prior_work_inode_and_bytes_preserved": true, "old_work_not_readiness_or_executed_on_retry": true, "foreign_paths_refused_without_repairs": 6, "work_link_retained_and_refused": true, "runtime_installed": false, "application_installed": false, "public_core_api_or_ui_verified": false}, "", "  ")
	if err := atomicWrite(filepath.Join(fixture, "proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_RUNTIME_ROOT_CACHE_PROOF", core.Hash(string(proof)))
}
