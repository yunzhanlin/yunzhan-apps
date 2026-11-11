//go:build linux

package executor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPhpMyAdminDatabaseSocketPinsIdentity(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mysql.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := dialPhpMyAdminDatabase(ctx, path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("dial an owned Unix listener through its held inode: %v", err)
	}
	defer client.Close()
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if client, err := dialPhpMyAdminDatabase(ctx, path, uint32(os.Geteuid()+1)); err == nil {
		client.Close()
		t.Fatal("accepted a socket belonging to another UID")
	}
	alias := filepath.Join(directory, "alias.sock")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if client, err := dialPhpMyAdminDatabase(ctx, alias, uint32(os.Geteuid())); err == nil {
		client.Close()
		t.Fatal("accepted a symlink in place of the socket")
	}
}
