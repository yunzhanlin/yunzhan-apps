//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func redisACLFixture() (core.RedisInstance, redisAuthSecret) {
	v := core.RedisInstance{ID: "0123456789abcdef0123456789abcdef", Name: "ACL fixture", ReleaseID: "redis-8.2.10", Port: 16379, MaxMemoryMB: 128, CreatedAt: "2026-10-24T00:00:00Z", AuthMode: core.RedisACLAuthMode}
	return v, redisAuthSecret{Format: 1, ID: v.ID, ReleaseID: v.ReleaseID, Port: v.Port, CreatedAt: v.CreatedAt, AdminPassword: strings.Repeat("ab", 32), AppPassword: strings.Repeat("cd", 32)}
}

func TestRedisACLSecretClosedIdentityAndHashOnlyConfig(t *testing.T) {
	instance, secret := redisACLFixture()
	raw, _ := json.Marshal(secret)
	if actual, err := decodeRedisAuth(raw, instance); err != nil || actual != secret {
		t.Fatal("valid exact credential refused", err)
	}
	for _, change := range []func(*redisAuthSecret){
		func(v *redisAuthSecret) { v.Format = 2 }, func(v *redisAuthSecret) { v.ID = strings.Repeat("e", 32) },
		func(v *redisAuthSecret) { v.ReleaseID = "redis-6.2.0" }, func(v *redisAuthSecret) { v.Port++ },
		func(v *redisAuthSecret) { v.CreatedAt = "different" }, func(v *redisAuthSecret) { v.AppPassword = v.AdminPassword },
		func(v *redisAuthSecret) { v.AdminPassword = strings.Repeat("z", 64) }, func(v *redisAuthSecret) { v.AppPassword = strings.Repeat("CD", 32) },
	} {
		v := secret
		change(&v)
		raw, _ := json.Marshal(v)
		if _, err := decodeRedisAuth(raw, instance); err == nil {
			t.Fatal("mismatched secret admitted")
		}
	}
	for _, raw := range [][]byte{append(append([]byte{}, raw...), []byte("{}")...), []byte(strings.Replace(string(raw), `"format":1`, `"unknown":1,"format":1`, 1)), []byte(strings.Repeat(" ", 4097))} {
		if _, err := decodeRedisAuth(raw, instance); err == nil {
			t.Fatal("unclosed or oversized secret admitted")
		}
	}
	config := redisInstanceConfig(instance, secret)
	if strings.Contains(config, secret.AdminPassword) || strings.Contains(config, secret.AppPassword) || !strings.Contains(config, "user default reset off\n") || !strings.Contains(config, "-@admin -@dangerous\n") || strings.Count(config, "user ") != 3 {
		t.Fatal("unsafe ACL configuration")
	}
	public, _ := json.Marshal(instance)
	var fields map[string]json.RawMessage
	if json.Unmarshal(public, &fields) != nil {
		t.Fatal("public instance is not JSON")
	}
	for _, forbidden := range []string{"password", "admin_password", "app_password"} {
		if _, present := fields[forbidden]; present {
			t.Fatal("instance contains private credential field")
		}
	}
	if strings.Contains(string(public), secret.AdminPassword) || strings.Contains(string(public), secret.AppPassword) {
		t.Fatal("instance leaks a credential value")
	}
	for i := 0; i < 2; i++ {
		v, err := newRedisAuthSecret(instance)
		if err != nil || !v.valid(instance) || v.AdminPassword == secret.AdminPassword || v.AppPassword == secret.AppPassword {
			t.Fatal("random generation/identity", err)
		}
	}
}

func TestRedisACLSecretFileRootMetadataNotPermissionProbe(t *testing.T) {
	instance, secret := redisACLFixture()
	dir := t.TempDir()
	file := filepath.Join(dir, redisAuthLeaf)
	if os.Geteuid() != 0 {
		raw, _ := json.Marshal(secret)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRedisAuthFile(file, instance); err == nil {
			t.Fatal("ordinary-user credential file admitted as Root-owned")
		}
		return // Genuine ordinary-user refusal, NOT positive Root-file coverage.
	}
	if err := writeRedisAuthSecret(dir, secret); err != nil {
		t.Fatal(err)
	}
	if got, err := readRedisAuthFile(file, instance); err != nil || got != secret {
		t.Fatal("Root0600 positive file", err)
	}
	original, _ := os.ReadFile(file)
	if err := writeRedisAuthSecret(dir, secret); err == nil {
		t.Fatal("existing credential overwritten")
	}
	for _, mode := range []os.FileMode{0000, 0640, 0666, 0700} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := readRedisAuthFile(file, instance); err == nil {
			t.Fatal("unsafe mode admitted", mode)
		}
		if err := os.Chmod(file, 0600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "hardlink")
	if err := os.Link(file, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readRedisAuthFile(file, instance); err == nil {
		t.Fatal("multiply-linked credential admitted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRedisAuthFile(link, instance); err == nil {
		t.Fatal("symbolic credential admitted")
	}
	if err := os.Chown(file, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := readRedisAuthFile(file, instance); err == nil {
		t.Fatal("foreign owner admitted")
	}
	if err := os.Chown(file, 0, 0); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file)
	if string(after) != string(original) {
		t.Fatal("refusal changed original secret bytes")
	}
}

func TestRedisACLRESPBoundedTypedReplies(t *testing.T) {
	for _, item := range []struct {
		raw   string
		value any
	}{
		{"+OK\r\n", "OK"}, {":-1\r\n", int64(-1)}, {"$-1\r\n", nil}, {"*0\r\n", []any{}},
		{"*2\r\n$1\r\n7\r\n*2\r\n$3\r\none\r\n$3\r\ntwo\r\n", []any{"7", []any{"one", "two"}}},
		{"$4\r\nx\r\ny\r\n", "x\r\ny"},
	} {
		got, err := newRedisRESPReader(strings.NewReader(item.raw)).value(0)
		if err != nil || !reflect.DeepEqual(got, item.value) {
			t.Fatal("RESP type mismatch", err)
		}
	}
	for _, raw := range []string{
		"", ">2\r\n", "$-2\r\n", "$1048577\r\n", ":9223372036854775808\r\n", ":+1\r\n", ":01\r\n",
		"*1024\r\n", strings.Repeat("*1\r\n", 10) + "+x\r\n", "+bad\rline\r\n", "+" + strings.Repeat("x", 4096) + "\r\n",
		"$2\r\nx\r\n", "*2\r\n+one\r\n", "$0\r\nXX",
	} {
		if _, err := newRedisRESPReader(strings.NewReader(raw)).value(0); err == nil {
			t.Fatal("unbounded/malformed RESP admitted")
		}
	}
	for _, code := range []string{"WRONGPASS", "NOAUTH", "NOPERM", "UNKNOWN"} {
		_, err := newRedisRESPReader(strings.NewReader("-" + code + " private-do-not-echo\r\n")).value(0)
		if err == nil || strings.Contains(err.Error(), "private-do-not-echo") {
			t.Fatal("peer error data disclosed")
		}
	}
	if _, err := redisRESPCommand([]string{"EVAL", strings.Repeat("x", redisCommandByteLimit)}); err == nil {
		t.Fatal("unbounded command admitted")
	}
	if _, err := redisRESPCommand(make([]string, 65)); err == nil {
		t.Fatal("unbounded argument count")
	}
	// The same limited reader is used across AUTH/SELECT/command, not renewed
	// for each frame or recursively decoded bulk.
	raw := "*3\r\n" + strings.Repeat("$1048576\r\n"+strings.Repeat("x", 1<<20)+"\r\n", 3)
	if _, err := newRedisRESPReader(strings.NewReader(raw)).value(0); err == nil {
		t.Fatal("aggregate byte cap bypassed")
	}
}

func TestRedisACLRESPRealPrivateStreamAUTHSELECTBeforeCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	password := strings.Repeat("ab", 32)
	go func() {
		reader := newRedisRESPReader(server)
		for index, expected := range [][]any{{"AUTH", "panel-admin", password}, {"SELECT", "3"}, {"SCAN", "0", "COUNT", "50"}} {
			actual, err := reader.value(0)
			if err != nil || !reflect.DeepEqual(actual, expected) {
				done <- errors.New("incorrect private AUTH/SELECT/command sequence")
				return
			}
			reply := "+OK\r\n"
			if index == 2 {
				reply = "*2\r\n$1\r\n0\r\n*1\r\n$5\r\nhello\r\n"
			}
			if _, err = io.WriteString(server, reply); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	actual, err := redisAuthenticatedCommand(context.Background(), client, "panel-admin", password, 3, "SCAN", "0", "COUNT", "50")
	if err != nil || !reflect.DeepEqual(actual, []any{"0", []any{"hello"}}) {
		t.Fatal("actual private RESP sequence", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRedisACLRESPAuthenticationFailureNeverExecutesOrEchoes(t *testing.T) {
	for _, bad := range []string{"-WRONGPASS do-not-echo-secret\r\n", "+NOT-OK\r\n"} {
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() {
			reader := newRedisRESPReader(server)
			if _, err := reader.value(0); err != nil {
				done <- err
				return
			}
			if _, err := io.WriteString(server, bad); err != nil {
				done <- err
				return
			}
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := reader.reader.ReadByte(); err == nil {
				done <- errors.New("command sent after refused AUTH")
				return
			}
			done <- nil
		}()
		_, err := redisAuthenticatedCommand(context.Background(), client, "panel-admin", strings.Repeat("ab", 32), 0, "PING")
		client.Close()
		if err == nil || strings.Contains(err.Error(), "do-not-echo") {
			t.Fatal("AUTH failure escaped")
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		server.Close()
	}
}

func TestRedisACLRESPCancellationClosesPrivateConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	read := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := newRedisRESPReader(server).value(0)
		if err == nil {
			close(read)
		}
	}()
	go func() {
		_, err := redisAuthenticatedCommand(ctx, client, "panel-admin", strings.Repeat("ab", 32), 0, "PING")
		done <- err
	}()
	select {
	case <-read:
	case <-time.After(time.Second):
		t.Fatal("AUTH not received")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled authentication succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not bound blocked read")
	}
}

func TestRedisACLRESPFixedCommandsAndNoLegacyFallback(t *testing.T) {
	instance, _ := redisACLFixture()
	instance.ID = core.ID() // Never inspect an existing host instance for this negative model.
	if err := validateRedisAuthMode(instance); err == nil {
		t.Fatal("missing secure file became permission for unauthenticated operation")
	}
	for _, command := range []string{"AUTH", "ACL", "CONFIG", "SHUTDOWN", "MODULE", "REPLICAOF", "DEBUG", "MIGRATE", ""} {
		client, server := net.Pipe()
		_, err := redisAuthenticatedCommand(context.Background(), client, "panel-admin", strings.Repeat("ab", 32), 0, command)
		client.Close()
		server.Close()
		if err == nil {
			t.Fatal("arbitrary management command admitted", command)
		}
	}
}
