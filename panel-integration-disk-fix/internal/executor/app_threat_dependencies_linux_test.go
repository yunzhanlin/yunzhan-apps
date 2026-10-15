//go:build linux

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestThreatIDSInstalledDependencyConstraintsDoNotAuthorizeLibraryUpgrades(t *testing.T) {
	for _, bad := range []string{"", "install ok unpacked\t2.39", "unpacked\t2.39", "installed\t-1", "installed\t2.39\ninstalled\t2.40", "installed\t2.39\nVersion=2.40"} {
		calls := 0
		s := New(Config{SystemRoot: t.TempDir(), Run: func(ctx context.Context, name string, args ...string) (string, error) {
			calls++
			if name != "/usr/bin/dpkg-query" {
				t.Fatal("malformed version reached compare", name, args)
			}
			return bad, nil
		}})
		if err := s.threatIDSCheckInstalledDependencies(context.Background(), "libc6 (>= 2.39)"); err == nil || calls != 1 {
			t.Fatal(bad, err, calls)
		}
	}
	compared := 0
	s := New(Config{SystemRoot: t.TempDir(), Run: func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/dpkg-query" {
			if strings.Join(args, " ") != "--show --showformat=${db:Status-Status}\t${Version} -- libc6" {
				t.Fatal(args)
			}
			return "installed\t2.41", nil
		}
		if name == "/usr/bin/dpkg" && strings.Join(args, " ") == "--compare-versions 2.41 ge 2.39" {
			compared++
			return "", nil
		}
		t.Fatal("unexpected mutation or unreviewed command", name, args)
		return "", errors.New("unexpected")
	}})
	if err := s.threatIDSCheckInstalledDependencies(context.Background(), "python3:any, libc6 (>= 2.39), procps, python3-yaml, lsb-base (>= 3.0-6)"); err != nil || compared != 1 {
		t.Fatal(err, compared)
	}
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/dpkg-query" {
			return "installed\t2.36", nil
		}
		return "", errors.New("version below bound")
	}
	if err := s.threatIDSCheckInstalledDependencies(context.Background(), "libc6 (>= 2.39)"); err == nil {
		t.Fatal("ABI failure accepted")
	}
	for _, bad := range []string{"libc6 (>= 2.39); id", "openssh-server", "libc6 | libbpf1"} {
		s.Config.Run = func(context.Context, string, ...string) (string, error) {
			t.Fatal("invalid expression reached host command")
			return "", nil
		}
		if err := s.threatIDSCheckInstalledDependencies(context.Background(), bad); err == nil {
			t.Fatal(bad)
		}
	}
}
