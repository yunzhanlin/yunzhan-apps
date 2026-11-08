//go:build linux

package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This executes the exact retained 1.0.0 writer as actual UID/GID33. Its open
// description survives Root's exchange, so the test checks the old writer's
// ownership fence rather than relying on the pathname's private parent.
func TestApacheCCArchiveLegacyWriterRefusesRootSealedOpenDescription(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires an explicit native Root compiler fixture")
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("native Root fixture requires its actual C compiler", err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	header, err := verifiedApacheCCAsset("apache-cc-log.h")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old-log.h"), header, 0600); err != nil {
		t.Fatal(err)
	}
	const program = `
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static int opened[2], resume_writer[2], pause_after_open;
static int paused_open(const char *path, int flags) {
    int fd = open(path, flags); char byte = 'x';
    if (pause_after_open && fd >= 0) {
        assert(write(opened[1], &byte, 1) == 1);
        assert(read(resume_writer[0], &byte, 1) == 1);
    }
    return fd;
}
#define open paused_open
#include "old-log.h"
#undef open
static void content_is(const char *name, const char *expected) {
    char data[256]; int fd = open(name, O_RDONLY); assert(fd >= 0);
    ssize_t n = read(fd, data, sizeof(data));
    assert(n == (ssize_t)strlen(expected) && memcmp(data, expected, n) == 0);
    assert(close(fd) == 0);
}
static void drop_worker(void) {
    assert(setgroups(0, NULL) == 0 && setgid(33) == 0 && setuid(33) == 0);
    assert(geteuid() == 33 && getegid() == 33);
}
int main(void) {
    char byte; int status;
    assert(geteuid() == 0 && pipe(opened) == 0 && pipe(resume_writer) == 0);
    int old = open("active.log", O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
    assert(old >= 0 && write(old, "original\n", 9) == 9 && fchown(old, 33, 33) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (child == 0) {
        assert(close(old) == 0); drop_worker(); pause_after_open = 1;
        _exit(yz_cc_log_append("active.log", "stale\n", 6) == 0 ? 0 : 71);
    }
    assert(read(opened[0], &byte, 1) == 1 && flock(old, LOCK_EX|LOCK_NB) == 0);
    int fresh = open("archive.log", O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
    assert(fresh >= 0 && fchown(fresh, 33, 33) == 0);
    assert(syscall(SYS_renameat2, AT_FDCWD, "active.log", AT_FDCWD, "archive.log", 2) == 0);
    assert(fchown(old, 0, 0) == 0 && fsync(old) == 0 && close(old) == 0);
    assert(write(resume_writer[1], "x", 1) == 1);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    content_is("archive.log", "original\n"); content_is("active.log", "");
    child = fork(); assert(child >= 0);
    if (child == 0) { drop_worker(); _exit(yz_cc_log_append("active.log", "current\n", 8) == 1 ? 0 : 72); }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    content_is("archive.log", "original\n"); content_is("active.log", "current\n");
    assert(close(fresh) == 0);
    puts("actual UID33 legacy stale-open refused by Root seal; original archive intact; fresh legacy append accepted");
    return 0;
}`
	if err := os.WriteFile(filepath.Join(dir, "writer.c"), []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-o", "writer", "writer.c")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile original writer: %v: %s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "writer"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil || !strings.Contains(string(out), "actual UID33 legacy stale-open refused") {
		t.Fatalf("actual legacy writer: %v: %s", err, out)
	}
}
