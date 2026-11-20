//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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

func TestThreatIDSIndependentArchiveOldWriter(t *testing.T) {
	if os.Getenv("PANEL_TEST_IDS_OWNED_WRITER") == "1" {
		if err := syscall.Setgroups([]int{}); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setgid(801); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setuid(800); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() != 800 || os.Getegid() != 801 {
			t.Fatal("owned writer did not drop its identity")
		}
		fd, err := unix.Openat(3, "eve.json", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "owned-producer")
		defer file.Close()
		fmt.Println("writer-ready uid=800 gid=801")
		pipe := os.NewFile(4, "owned-trigger")
		defer pipe.Close()
		var trigger [1]byte
		if _, err := io.ReadFull(pipe, trigger[:]); err != nil {
			t.Fatal(err)
		}
		if other, err := os.OpenFile(os.Getenv("PANEL_TEST_IDS_FINAL_PATH"), os.O_WRONLY, 0); err == nil {
			other.Close()
			t.Fatal("nonroot writer reopened the private archive by name")
		}
		if _, err := file.WriteAt([]byte("CHANGED"), 0); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("old-writer-completed uid=800 gid=801")
		return
	}

	s := threatIDSRotationRootFixture(t)
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	logs := filepath.Join(s.Config.SystemRoot, "owned-writer-logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(logs, 800, 801); err != nil {
		t.Fatal(err)
	}
	initial := []byte("original-closed-alert-metadata\n")
	live := filepath.Join(logs, "eve.json")
	if err := os.WriteFile(live, initial, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(live, 800, 801); err != nil {
		t.Fatal(err)
	}
	old, err := os.Lstat(live)
	if err != nil {
		t.Fatal(err)
	}
	identity := old.Sys().(*syscall.Stat_t)
	id := core.ID()
	path := s.systemPath("/var/lib/panel-network-ids/history/eve-" + id + ".json")
	directory, err := os.Open(logs)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	triggerRead, triggerWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer triggerRead.Close()
	defer triggerWrite.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestThreatIDSIndependentArchiveOldWriter$", "-test.v", "-test.count=1")
	child.Env = append(os.Environ(), "PANEL_TEST_IDS_OWNED_WRITER=1", "PANEL_TEST_IDS_FINAL_PATH="+path)
	child.ExtraFiles = []*os.File{directory, triggerRead}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	ready := make(chan error, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if strings.TrimSpace(line) == "writer-ready uid=800 gid=801" {
				ready <- nil
				return
			}
			if err != nil {
				ready <- fmt.Errorf("owned writer readiness: %w", err)
				return
			}
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("owned writer did not open its own producer file")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, live, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		t.Fatal(err)
	}
	pending := &threatIDSRotationPending{
		CopyFormat: 2, ID: id, At: core.Now(), Device: uint64(identity.Dev), Inode: identity.Ino,
		UID: 800, GID: 801, Revision: 1, RuntimeSHA: core.Hash("runtime"), UnitSHA: core.Hash("unit"),
	}
	record := filepath.Join(s.Config.SystemRoot, "owned-seal-record.json")
	sealed, err := threatIDSSealArchive(context.Background(), path, pending, account, func() error {
		return moduleWrite(record, pending)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := triggerWrite.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	tail, readErr := io.ReadAll(reader)
	waitErr := child.Wait()
	if readErr != nil || waitErr != nil || !strings.Contains(string(tail), "old-writer-completed uid=800 gid=801") {
		t.Fatal("owned nonroot write failed", readErr, waitErr, string(tail), stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("an old nonroot writer changed the sealed archive: expected_sha=%s actual_sha=%s original_inode=%d sealed_inode=%d", core.Hash(string(initial)), core.Hash(string(got)), identity.Ino, sealed.Inode)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if owner.Ino == identity.Ino || owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 1 || info.Mode().Perm() != 0600 {
		t.Fatal("archive is not an independent root private inode")
	}
	if _, err := s.threatIDSArchiveFile(sealed); err != nil {
		t.Fatal("old writer invalidated the independent reader", err)
	}
	producer := filepath.Join(filepath.Dir(path), threatIDSProducerName(id))
	preserved, err := os.ReadFile(producer)
	if err != nil || bytes.Equal(preserved, initial) {
		t.Fatal("the nonroot write did not remain confined to the preserved original", err)
	}
	producerInfo, err := os.Lstat(producer)
	if err != nil {
		t.Fatal(err)
	}
	producerOwner := producerInfo.Sys().(*syscall.Stat_t)
	if producerOwner.Ino != identity.Ino || producerOwner.Uid != 0 || producerOwner.Gid != 0 || producerOwner.Nlink != 1 || producerInfo.Mode().Perm() != 0600 {
		t.Fatal("producer identity or private metadata not preserved")
	}
	if sealed.Source == nil || sealed.Source.Inode != identity.Ino || sealed.Source.SHA != core.Hash(string(initial)) || sealed.Source.UID != 800 || sealed.Source.GID != 801 {
		t.Fatal("original producer witness was lost or rewritten after the old write")
	}
	rotation := threatIDSRotation{Format: 2, Archives: []threatIDSArchive{sealed}, Retired: []threatIDSArchive{}}
	if err := s.writeThreatIDSRotation(rotation); err != nil {
		t.Fatal(err)
	}
	sources, summary, err := s.threatIDSHistorySources(context.Background())
	if err != nil || len(sources) != 1 || summary.IndependentCopies != 1 || summary.LegacyArchives != 0 || summary.PreservedProducerWitnesses != 1 {
		t.Fatal("preserved producer changes invalidated authoritative history", summary, err)
	}
	data, err := io.ReadAll(sources[0].Reader)
	if err != nil || !bytes.Equal(data, initial) {
		t.Fatal("history did not return the exact independent bytes", err)
	}
}
