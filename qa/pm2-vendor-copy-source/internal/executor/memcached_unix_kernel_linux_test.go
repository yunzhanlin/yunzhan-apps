//go:build linux

package executor

import (
	"context"
	"os"
	"strings"
	"testing"
)

func memcachedUnixKernelFixture() (string, map[string]string) {
	id := strings.Repeat("b", 64)
	f := make([]string, 22)
	for i := range f {
		f[i] = "0"
	}
	f[0], f[19] = "S", "12345"
	base := "/proc/42/"
	cg := "/sys/fs/cgroup/system.slice/docker-" + id + ".scope/"
	return id, map[string]string{
		base + "stat":      "42 (memcached (worker)) " + strings.Join(f, " ") + "\n",
		base + "status":    strings.Replace(taskIdentityFixtureStatus("11211"), "ffffffffffffffff", "0000000000000000", 1) + "Gid:\t11211 11211 11211 11211\nGroups:\t11211\n",
		base + "cgroup":    "0::/system.slice/docker-" + id + ".scope\n",
		base + "limits":    "Limit                     Soft Limit           Hard Limit           Units\nMax open files            256                  256                  files\n",
		base + "mountinfo": "100 99 0:20 / / ro,relatime - overlay overlay rw,lowerdir=/unrelated\n",
		cg + "memory.max":  "201326592\n", cg + "memory.swap.max": "0\n", cg + "pids.max": "32\n", cg + "cpu.max": "100000 100000\n",
	}
}

func TestMemcachedUnixKernelRequiresEnforcedLimitsAndStableNonRootProcess(t *testing.T) {
	for _, name := range []string{"valid", "unlimited-memory", "larger-memory", "swap", "unlimited-pids", "unlimited-cpu", "double-cpu", "missing-controller", "root", "saved-root", "active-cap", "bounding-cap", "duplicate-bound", "nnp", "writable-root", "duplicate-root", "ulimit", "configured-not-effective-ulimit", "too-small-ulimit", "mismatched-ulimit", "foreign-group", "v1-group", "multiple-groups", "pid-reused", "zombie", "group-moved", "symlink-read-error"} {
		t.Run(name, func(t *testing.T) {
			id, files := memcachedUnixKernelFixture()
			base := "/proc/42/"
			cg := "/sys/fs/cgroup/system.slice/docker-" + id + ".scope/"
			switch name {
			case "unlimited-memory":
				files[cg+"memory.max"] = "max\n"
			case "larger-memory":
				files[cg+"memory.max"] = "268435456\n"
			case "swap":
				files[cg+"memory.swap.max"] = "1024\n"
			case "unlimited-pids":
				files[cg+"pids.max"] = "max\n"
			case "unlimited-cpu":
				files[cg+"cpu.max"] = "max 100000\n"
			case "double-cpu":
				files[cg+"cpu.max"] = "200000 100000\n"
			case "missing-controller":
				delete(files, cg+"memory.max")
			case "root":
				files[base+"status"] = strings.ReplaceAll(files[base+"status"], "11211", "0")
			case "saved-root":
				files[base+"status"] = strings.Replace(files[base+"status"], "11211 11211 11211 11211", "11211 11211 0 11211", 1)
			case "active-cap":
				files[base+"status"] = strings.Replace(files[base+"status"], "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1)
			case "bounding-cap":
				files[base+"status"] = strings.Replace(files[base+"status"], "CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001", 1)
			case "duplicate-bound":
				files[base+"status"] += "CapBnd:\t0000000000000000\n"
			case "nnp":
				files[base+"status"] = strings.Replace(files[base+"status"], "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)
			case "writable-root":
				files[base+"mountinfo"] = strings.Replace(files[base+"mountinfo"], "/ / ro,", "/ / rw,", 1)
			case "duplicate-root":
				files[base+"mountinfo"] += files[base+"mountinfo"]
			case "ulimit":
				files[base+"limits"] = strings.ReplaceAll(files[base+"limits"], "256", "65535")
			case "configured-not-effective-ulimit":
				files[base+"limits"] = strings.ReplaceAll(files[base+"limits"], "256", "1024")
			case "too-small-ulimit":
				files[base+"limits"] = strings.ReplaceAll(files[base+"limits"], "256", "255")
			case "mismatched-ulimit":
				files[base+"limits"] = strings.Replace(files[base+"limits"], "256", "255", 1)
			case "foreign-group":
				files[base+"cgroup"] = "0::/system.slice/docker-" + strings.Repeat("e", 64) + ".scope\n"
			case "v1-group":
				files[base+"cgroup"] = "1:name=systemd:/docker/" + id + "\n"
			case "multiple-groups":
				files[base+"cgroup"] += files[base+"cgroup"]
			case "zombie":
				files[base+"stat"] = strings.Replace(files[base+"stat"], ") S ", ") Z ", 1)
			}
			reads := map[string]int{}
			read := func(path string, limit int64) ([]byte, error) {
				reads[path]++
				value, ok := files[path]
				if !ok || int64(len(value)) > limit || name == "symlink-read-error" {
					return nil, os.ErrPermission
				}
				if name == "pid-reused" && path == base+"stat" && reads[path] == 2 {
					value = strings.Replace(value, "12345", "12346", 1)
				}
				if name == "group-moved" && path == base+"cgroup" && reads[path] == 2 {
					value = "0::/foreign\n"
				}
				return []byte(value), nil
			}
			err := memcachedUnixKernel(context.Background(), 42, id, memcachedUnixAccount{11211, 11211}, read)
			if (name == "valid") != (err == nil) {
				t.Fatal("kernel verification result", name, err)
			}
		})
	}
}
