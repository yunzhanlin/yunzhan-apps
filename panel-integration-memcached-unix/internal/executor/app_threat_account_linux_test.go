//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreatIDSAccountPrivateOwnershipAndClosedGroup(t *testing.T) {
	root := t.TempDir()
	v := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	passwd := "panel-network-ids:x:800:801::/nonexistent:/usr/sbin/nologin\n"
	group := "panel-network-ids:x:801:\n"
	groups := "801\n"
	service := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security"), Run: func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/id" && len(args) == 2 && args[0] == "-G" && args[1] == "panel-network-ids" {
			return groups, nil
		}
		if name != "/usr/bin/getent" || len(args) != 2 || args[1] != "panel-network-ids" {
			t.Fatal("unexpected account operation", name, args)
		}
		if args[0] == "passwd" {
			return passwd, nil
		}
		if args[0] == "group" {
			return group, nil
		}
		return "", errors.New("unknown getent")
	}})
	record := filepath.Join(service.moduleDir("network-threat-detection"), "capture-account.json")
	if _, err := service.threatIDSAccount(context.Background()); !os.IsNotExist(err) {
		t.Fatal("missing account incorrectly adopted", err)
	}
	if err := moduleWrite(record, v); err != nil {
		t.Fatal(err)
	}
	if actual, err := service.threatIDSAccount(context.Background()); err != nil || actual != v {
		t.Fatal(actual, err)
	}
	for _, bad := range []string{strings.Replace(passwd, ":800:", ":0:", 1), strings.Replace(passwd, "/nonexistent", "/root", 1), strings.Replace(passwd, "/usr/sbin/nologin", "/bin/bash", 1), passwd + passwd, strings.Replace(passwd, ":x:", ":hash:", 1), strings.Replace(passwd, "::/nonexistent", ":other:/nonexistent", 1)} {
		previous := passwd
		passwd = bad
		if _, err := service.threatIDSAccount(context.Background()); err == nil {
			t.Fatal("foreign/interactive account adopted", bad)
		}
		passwd = previous
	}
	group = "panel-network-ids:x:801:another-user\n"
	if _, err := service.threatIDSAccount(context.Background()); err == nil {
		t.Fatal("additional group member accepted")
	}
	group = "panel-network-ids:x:801:\n"
	for _, bad := range []string{"", "0\n", "801 0\n", "801 27\n", "801 801\n", "801\nunknown\n"} {
		groups = bad
		if _, err := service.threatIDSAccount(context.Background()); err == nil {
			t.Fatal("unknown or extra supplementary group accepted", bad)
		}
	}
	groups = "801\n"
	if err := os.Chmod(record, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := service.threatIDSAccount(context.Background()); err == nil {
		t.Fatal("public ownership record accepted")
	}
	if err := service.prepareThreatIDSAccount(context.Background()); err == nil {
		t.Fatal("fixture started actual account creation")
	}
	for _, invalid := range []threatIDSAccount{{}, {Format: 2, UID: 800, GID: 801}, {Format: 1, UID: 0, GID: 801}, {Format: 1, UID: 800, GID: 0}, {Format: 1, UID: 1000, GID: 801}, {Format: 1, UID: 800, GID: 1000}} {
		if validateThreatIDSAccount(invalid) == nil {
			t.Fatal("invalid dedicated account accepted", invalid)
		}
	}
}
