package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A real process pauses after opening the active sink. The parent atomically
// replaces the name before the child takes its inode lock. The archive must
// retain all its original bytes; only a fresh open may append to the new sink.
func TestApacheCCRotationWriterRejectsStaleOpenedSink(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("requires a native C compiler")
	}
	dir := t.TempDir()
	header, err := os.ReadFile("assets/apache-cc-log-v2.h")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "log.h"), header, 0600); err != nil {
		t.Fatal(err)
	}
	const program = `
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static int opened[2], resume_writer[2], pause_after_open;
static int paused_open(const char *path, int flags) {
    int fd = open(path, flags);
    char byte = 'x';
    if (pause_after_open && fd >= 0) {
        assert(write(opened[1], &byte, 1) == 1);
        assert(read(resume_writer[0], &byte, 1) == 1);
    }
    return fd;
}
#define open paused_open
#include "log.h"
#undef open
static void create_file(const char *name, const char *value) {
    int fd = open(name, O_WRONLY|O_CREAT|O_EXCL, 0600);
    size_t n = strlen(value);
    assert(fd >= 0 && write(fd, value, n) == (ssize_t)n && close(fd) == 0);
}
static void content_is(const char *name, const char *expected) {
    char data[256]; int fd = open(name, O_RDONLY);
    assert(fd >= 0); ssize_t n = read(fd, data, sizeof(data));
    assert(n == (ssize_t)strlen(expected) && memcmp(data, expected, n) == 0);
    assert(close(fd) == 0);
}
int main(void) {
    char byte; int status;
    assert(pipe(opened) == 0 && pipe(resume_writer) == 0);
    create_file("active.log", "original\n");
    pid_t child = fork(); assert(child >= 0);
    if (child == 0) {
        pause_after_open = 1;
        int result = yz_cc_log_append("active.log", "stale\n", 6);
        _exit(result == 0 ? 0 : 71);
    }
    assert(read(opened[0], &byte, 1) == 1);
    assert(rename("active.log", "archive.log") == 0);
    create_file("active.log", "");
    assert(write(resume_writer[1], "x", 1) == 1);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    content_is("archive.log", "original\n"); content_is("active.log", "");
    assert(yz_cc_log_append("active.log", "current\n", 8) == 1);
    content_is("active.log", "current\n"); content_is("archive.log", "original\n");
    assert(rename("active.log", "second.log") == 0);
    assert(symlink("archive.log", "active.log") == 0);
    assert(yz_cc_log_append("active.log", "bad\n", 4) == 0);
    content_is("archive.log", "original\n");
    assert(unlink("active.log") == 0);
    assert(yz_cc_log_append("active.log", "absent\n", 7) == 0);
    puts("stale-open rejected; archive intact; fresh append accepted; symlink and absence rejected");
    return 0;
}`
	if err := os.WriteFile(filepath.Join(dir, "writer.c"), []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-o", "writer", "writer.c")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v: %s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "writer"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil || !strings.Contains(string(out), "archive intact") {
		t.Fatalf("native writer: %v: %s", err, out)
	}
}
