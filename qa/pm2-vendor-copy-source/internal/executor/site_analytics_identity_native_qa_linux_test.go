//go:build linux && qa_analytics_identity

package executor

import (
	"bytes"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func nativeAnalyticsIdentityFixture(t *testing.T) (*Service, core.Site, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("This explicitly selected private native QA requires root in an owned isolated guest")
	}
	root := t.TempDir()
	for _, path := range []string{"etc/panel", "var/lib/panel"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	key := bytes.Repeat([]byte{0x71}, 32)
	if err := os.WriteFile(filepath.Join(root, "var/lib/panel/credential-key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	site := core.Site{ID: core.ID(), Domain: "owned-analytics.example", Settings: core.DefaultSiteSettings(core.SiteSettings{AnalyticsEndpoint: "127.0.0.1:19100"})}
	site.Settings.AnalyticsProxyIdentity, _ = core.AnalyticsProxyIdentity(key, site.ID)
	return New(Config{SystemRoot: root}), site, root
}

func TestNativeAnalyticsProxyIdentityPrivateFileAndStableRevalidation(t *testing.T) {
	s, site, root := nativeAnalyticsIdentityFixture(t)
	if err := s.prepareSiteAnalyticsIdentity(site); err != nil {
		t.Fatal(err)
	}
	path := s.systemPath(siteAnalyticsIdentityPath(site))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := core.AnalyticsProxyToken(bytes.Repeat([]byte{0x71}, 32), site.ID)
	if !bytes.Contains(original, []byte(token)) || !bytes.Contains(original, []byte(core.AnalyticsProxyClientHeader+" $remote_addr;")) {
		t.Fatal("Private include does not carry its actual managed client contract")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode().Perm() != 0600 || before.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("Private include is not root 0600", err)
	}
	if err := s.prepareSiteAnalyticsIdentity(site); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Lstat(path)
	b, a := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if b.Dev != a.Dev || b.Ino != a.Ino || b.Size != a.Size || b.Mtim != a.Mtim || b.Ctim != a.Ctim {
		t.Fatal("Known immutable include was rewritten during revalidation")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(original, current) {
		t.Fatal("Revalidation changed private bytes")
	}
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", "import sys\ntry:open(sys.argv[1],'rb').read()\nexcept PermissionError:sys.exit(0)\nexcept Exception:sys.exit(4)\nelse:sys.exit(3)", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	if out, err := cmd.CombinedOutput(); err != nil || len(out) != 0 {
		t.Fatal("Unprivileged process was not denied private include access", err)
	}
	if strings.Contains(siteAnalyticsProxy(site), token) || bytes.Contains(original, bytes.Repeat([]byte{0x71}, 32)) {
		t.Fatal("Collector token or primary key leaked into public site config")
	}
	if dir, err := os.Lstat(filepath.Join(root, "etc/panel/analytics-ingress")); err != nil || dir.Mode().Perm() != 0700 {
		t.Fatal("Private directory mode is incorrect", err)
	}
}

func TestNativeAnalyticsProxyIdentityRejectsUntrustedKeyAndParents(t *testing.T) {
	for _, name := range []string{"key_mode", "key_owner", "key_symlink", "key_hardlink", "key_fifo", "key_short", "key_changed", "key_missing", "parent_writable", "private_directory_mode", "private_directory_symlink", "identity_changed", "unknown_inventory"} {
		t.Run(name, func(t *testing.T) {
			s, site, root := nativeAnalyticsIdentityFixture(t)
			key := filepath.Join(root, "var/lib/panel/credential-key")
			private := filepath.Join(root, "etc/panel/analytics-ingress")
			var err error
			switch name {
			case "key_mode":
				err = os.Chmod(key, 0644)
			case "key_owner":
				err = os.Chown(key, 65534, 65534)
			case "key_symlink":
				target := filepath.Join(root, "owned-original-key")
				if err = os.Rename(key, target); err == nil {
					err = os.Symlink(target, key)
				}
			case "key_hardlink":
				err = os.Link(key, filepath.Join(root, "owned-original-key-copy"))
			case "key_fifo":
				if err = os.Rename(key, filepath.Join(root, "owned-original-key")); err == nil {
					err = syscall.Mkfifo(key, 0600)
				}
			case "key_short":
				err = os.WriteFile(key, []byte("short"), 0600)
			case "key_changed":
				err = os.WriteFile(key, bytes.Repeat([]byte{0x72}, 32), 0600)
			case "key_missing":
				err = os.Rename(key, filepath.Join(root, "owned-original-key"))
			case "parent_writable":
				err = os.Chmod(filepath.Join(root, "etc/panel"), 0777)
			case "private_directory_mode":
				if err = os.Mkdir(private, 0700); err == nil {
					err = os.Chmod(private, 0755)
				}
			case "private_directory_symlink":
				target := filepath.Join(root, "owned-original-directory")
				if err = os.Mkdir(target, 0700); err == nil {
					err = os.Symlink(target, private)
				}
			case "identity_changed":
				site.Settings.AnalyticsProxyIdentity = strings.Repeat("a", 64)
			case "unknown_inventory":
				if err = os.Mkdir(private, 0700); err == nil {
					err = os.WriteFile(filepath.Join(private, "unexpected"), []byte("owned sentinel"), 0600)
				}
			}
			if err != nil {
				t.Fatal("Unable to prepare isolated refusal condition", err)
			}
			if err := s.prepareSiteAnalyticsIdentity(site); err == nil {
				t.Fatal("Untrusted source was adopted", name)
			}
			if _, err := os.Lstat(s.systemPath(siteAnalyticsIdentityPath(site))); !os.IsNotExist(err) {
				t.Fatal("Rejected source unexpectedly created the include", err)
			}
		})
	}
}

func TestNativeAnalyticsProxyIdentityPreservesChangedOrPartialOriginal(t *testing.T) {
	for _, name := range []string{"content", "mode", "owner", "symlink", "hardlink", "partial"} {
		t.Run(name, func(t *testing.T) {
			s, site, root := nativeAnalyticsIdentityFixture(t)
			if err := s.prepareSiteAnalyticsIdentity(site); err != nil {
				t.Fatal(err)
			}
			path := s.systemPath(siteAnalyticsIdentityPath(site))
			var err error
			switch name {
			case "content":
				err = os.WriteFile(path, []byte("owned changed original\n"), 0600)
			case "mode":
				err = os.Chmod(path, 0644)
			case "owner":
				err = os.Chown(path, 65534, 65534)
			case "symlink":
				target := filepath.Join(root, "owned-original-include")
				if err = os.Rename(path, target); err == nil {
					err = os.Symlink(target, path)
				}
			case "hardlink":
				err = os.Link(path, filepath.Join(root, "owned-original-include-copy"))
			case "partial":
				err = os.Truncate(path, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.prepareSiteAnalyticsIdentity(site); err == nil {
				t.Fatal("Changed or partial file was silently accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
				t.Fatal("Refusal modified original file identity", err)
			}
		})
	}
}

func TestNativeAnalyticsProxyIdentityCapacityRefusesWithoutDeletion(t *testing.T) {
	s, site, root := nativeAnalyticsIdentityFixture(t)
	private := filepath.Join(root, "etc/panel/analytics-ingress")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2048; i++ {
		if err := os.WriteFile(filepath.Join(private, core.ID()+"-"+strings.Repeat("a", 64)+".conf"), []byte("# owned capacity fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.prepareSiteAnalyticsIdentity(site); err == nil {
		t.Fatal("Exceeded private inventory capacity")
	}
	entries, err := os.ReadDir(private)
	if err != nil || len(entries) != 2048 {
		t.Fatal("Capacity refusal removed original entries", err)
	}
}
