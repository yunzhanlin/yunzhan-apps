//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

var errMemcachedApply = errors.New("Memcached 原事务应用或配置发布结果无法核对；保留原证据，不重放")

// Anonymous sealed input, not a mutable project .env/YAML file or a supplied
// executable. ExtraFiles maps this single descriptor to child fd 3. Its bytes
// cannot be changed by another process after validation or between CLI reads.
func memcachedComposeInput(raw []byte) (*os.File, error) {
	if len(raw) == 0 || len(raw) > 48<<10 {
		return nil, errMemcachedApply
	}
	fd, err := unix.MemfdCreate("yunzhan-memcached-compose", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errMemcachedApply
	}
	f := os.NewFile(uintptr(fd), "sealed-memcached-compose")
	fail := func() (*os.File, error) { f.Close(); return nil, errMemcachedApply }
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		return fail()
	}
	if _, err := f.Seek(0, 0); err != nil {
		return fail()
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return fail()
	}
	actual, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || actual != seals {
		return fail()
	}
	return f, nil
}

func memcachedComposeCommand(ctx context.Context, project, engine string, input *os.File) (*exec.Cmd, error) {
	if ctx == nil || ctx.Err() != nil || input == nil || !core.ValidID(project) || engine != "panel_"+project[:12] {
		return nil, errMemcachedApply
	}
	seals, err := unix.FcntlInt(input.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals != (unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL) {
		return nil, errMemcachedApply
	}
	// Docker may launch Compose as a separate CLI plugin. Address OUR held
	// sealed descriptor, not an assumed fd inherited by the plugin subprocess.
	sealed := "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(input.Fd()), 10)
	cmd := exec.CommandContext(ctx, "/usr/bin/docker", "compose", "--env-file", "/dev/null", "--project-directory", filepath.Join(dockerProjects, project), "--project-name", engine, "--file", sealed, "up", "--pull", "never", "--no-build", "--no-deps", "--force-recreate", "--detach", "--wait", "--wait-timeout", "150", "memcached")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "COMPOSE_DISABLE_ENV_FILE=1"}
	cmd.ExtraFiles = []*os.File{input}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}

// No retry, alternate command, pull, tag, stop/down or cleanup after an unknown
// CLI outcome. The original worker decides observation/known-outcome rollback.
func memcachedComposeApply(ctx context.Context, seed core.MemcachedUpdateRecord, rollback bool) error {
	var raw []byte
	var err error
	if rollback {
		raw, err = core.MemcachedComposeRollback(seed.Plan)
	} else {
		raw, err = core.MemcachedComposeUpdateTarget(seed.Plan)
	}
	if err != nil {
		return errMemcachedApply
	}
	f, err := memcachedComposeInput(raw)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd, err := memcachedComposeCommand(ctx, seed.Dispatch.ProjectID, "panel_"+seed.Dispatch.ProjectID[:12], f)
	if err != nil {
		return err
	}
	output := &boundedBuffer{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = output, output
	return withDockerMutation(ctx, func(context.Context) error {
		if err := cmd.Run(); err != nil {
			return errMemcachedApply
		}
		return nil
	})
}

// Atomic exchange preserves both the held old inode and prepared new inode.
// There is no overwrite/rename fallback on unsupported filesystems. Any lost
// durability/identity proof leaves BOTH files for the original transaction;
// never exchange back, delete or recreate in response to an uncertain result.
func (d *composeUpdateDirectory) publishMemcachedCompose(ctx context.Context, seed core.MemcachedUpdateRecord, rollback bool, original, originalMetadata os.FileInfo) error {
	if ctx == nil || ctx.Err() != nil || core.ValidateMemcachedUpdateRecord(seed) != nil || !d.current() {
		return errMemcachedApply
	}
	current, info, err := d.read("compose.yaml", 48<<10)
	if err != nil || !sameComposeUpdateFile(original, info) || core.Hash(string(current)) != seed.Plan.ComposeSHA256 {
		return errMemcachedApply
	}
	metadata, mi, err := d.read("metadata.json", 16<<10)
	if err != nil || !sameComposeUpdateFile(originalMetadata, mi) || core.Hash(string(metadata)) != seed.Plan.MetadataSHA256 {
		return errMemcachedApply
	}
	var raw []byte
	if rollback {
		raw, err = core.MemcachedComposeRollback(seed.Plan)
	} else {
		raw, err = core.MemcachedComposeUpdateTarget(seed.Plan)
	}
	if err != nil {
		return errMemcachedApply
	}
	name := "compose.publish-" + seed.Dispatch.JobID + ".yaml"
	if rollback {
		name = "compose.rollback-" + seed.Dispatch.JobID + ".yaml"
	}
	if ruleFeedStoreWrite(d.root, name, raw, 0600) != nil || ruleFeedStoreSync(d.root) != nil {
		return errMemcachedApply
	}
	prepared, preparedInfo, err := geoStoreReadIdentity(d.root, name, 48<<10)
	if err != nil || !bytes.Equal(prepared, raw) || ctx.Err() != nil {
		return errMemcachedApply
	}
	before, si, err := d.read("compose.yaml", 48<<10)
	ma, mai, me := d.read("metadata.json", 16<<10)
	if err != nil || me != nil || !sameComposeUpdateFile(info, si) || !bytes.Equal(before, current) || !sameComposeUpdateFile(mi, mai) || !bytes.Equal(ma, metadata) || !d.current() {
		return errMemcachedApply
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return errMemcachedApply
	}
	defer dir.Close()
	if ctx.Err() != nil || unix.Renameat2(int(dir.Fd()), name, int(dir.Fd()), "compose.yaml", unix.RENAME_EXCHANGE) != nil {
		return errMemcachedApply
	}
	if dir.Sync() != nil {
		return errMemcachedApply
	}
	after, ai, err := d.read("compose.yaml", 48<<10)
	backup, bi, be := geoStoreReadIdentity(d.root, name, 48<<10)
	ma, mai, me = d.read("metadata.json", 16<<10)
	if err != nil || be != nil || me != nil || !os.SameFile(ai, preparedInfo) || !os.SameFile(bi, original) || !bytes.Equal(after, raw) || !bytes.Equal(backup, current) || !sameComposeUpdateFile(mi, mai) || !bytes.Equal(ma, metadata) || !d.current() || ctx.Err() != nil {
		return errMemcachedApply
	}
	// Avoid returning CLI output, config or environment through a job error.
	return nil
}

// File names and invocation are always derived internally, never from YAML,
// HTTP fields, Docker inspection labels or a caller-provided project path.
func memcachedProjectEngine(project string) string {
	if !core.ValidID(project) || strings.Contains(project, "/") {
		return ""
	}
	return "panel_" + project[:12]
}
