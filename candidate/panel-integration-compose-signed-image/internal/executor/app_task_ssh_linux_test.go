//go:build linux

package executor

import (
	"context"
	"os"
	"slices"
	"testing"
)

func TestTaskOpenSSHInventoryRecognizesActualAuthenticatedSocket(t *testing.T) {
	if os.Getenv("PANEL_TASK_INVENTORY_NATIVE") != "isolated-arm64" {
		t.Skip("requires the isolated Ubuntu ARM64 guest and a real SSH login")
	}
	hostname, err := os.Hostname()
	if err != nil || hostname != "lima-panel-openlitespeed-c92r2-arm64-qa" || os.Geteuid() != 0 {
		t.Fatal("unexpected native test host")
	}
	inode := os.Getenv("PANEL_QA_SSH_FIXTURE_INODE")
	unauthenticated := os.Getenv("PANEL_QA_SSH_FIXTURE_UNAUTH_INODE")
	name := os.Getenv("PANEL_QA_SSH_FIXTURE_USERNAME")
	if inode == "" || name == "" || unauthenticated == "" || unauthenticated == inode {
		t.Fatal("missing independently observed TCP socket or test account")
	}
	out := taskInventory{View: "ssh"}
	if err := New(Config{}).taskOpenSSHInventory(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(out.Rows, func(row map[string]string) bool { return row["session"] == "ssh:"+unauthenticated }) {
		t.Fatal("an unauthenticated connection was reported as a session")
	}
	if !slices.ContainsFunc(out.Rows, func(row map[string]string) bool {
		return row["session"] == "ssh:"+inode && row["name"] == name && row["source"] == "OpenSSH" &&
			row["remote_host"] == "127.0.0.1" && row["terminal"] != "" && row["state"] == "active"
	}) {
		for _, row := range out.Rows {
			if row["remote_host"] == "127.0.0.1" {
				t.Logf("Observed loopback record %q for %q on %q", row["session"], row["name"], row["terminal"])
			}
		}
		t.Logf("Expected loopback socket inode %s for %q", inode, name)
		t.Fatal("verified native SSH session not found", len(out.Rows), out.Partial)
	}
	t.Log("Matched the authenticated OpenSSH child and its actual established TCP socket")
}
