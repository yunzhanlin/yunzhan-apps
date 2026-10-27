//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamAccountNativeFixture(t *testing.T) string {
	t.Helper()
	anchor := os.Getenv("PANEL_LBSTREAM_ACCOUNT_QA_ROOT")
	if anchor == "" {
		t.Skip("explicit isolated Root ownership filesystem models only, not account creation")
	}
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/lbstream-account-native24blif-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(anchor) ||
		threatIDSTrustedParents(anchor, false) != nil || os.TempDir() != anchor+"/tmp" {
		t.Fatal("actual closed native QA root is required")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBalanceStreamAccountNativePrivateStoreOnlyOriginalInodes(t *testing.T) {
	for _, fault := range []string{"valid", "directory-mode", "directory-sticky", "directory-symlink", "unknown-entry", "record-directory", "record-fifo", "record-symlink", "record-hardlink", "record-mode", "record-oversize"} {
		t.Run(fault, func(t *testing.T) {
			parent := streamAccountNativeFixture(t)
			path := filepath.Join(parent, "identity")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			intent, _ := streamAccountFixture()
			raw := loadBalanceStreamAccountBytes(intent)
			record := filepath.Join(path, "account-intent.json")
			write := func(file string, b []byte, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(file, b, mode); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "directory-mode":
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory-sticky":
				if err := os.Chmod(path, 0700|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				if err := os.Rename(path, path+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-original", path); err != nil {
					t.Fatal(err)
				}
			case "unknown-entry":
				write(filepath.Join(path, "foreign.json"), []byte("foreign"), 0600)
			case "record-directory":
				if err := os.Mkdir(record, 0700); err != nil {
					t.Fatal(err)
				}
			case "record-fifo":
				if err := syscall.Mkfifo(record, 0600); err != nil {
					t.Fatal(err)
				}
			case "record-symlink", "record-hardlink":
				outside := filepath.Join(parent, "original.json")
				write(outside, raw, 0600)
				link := os.Symlink
				if fault == "record-hardlink" {
					link = os.Link
				}
				if err := link(outside, record); err != nil {
					t.Fatal(err)
				}
			case "record-mode":
				write(record, raw, 0600)
				if err := os.Chmod(record, 0640); err != nil {
					t.Fatal(err)
				}
			case "record-oversize":
				write(record, bytes.Repeat([]byte("x"), 2049), 0600)
			default:
				write(record, raw, 0600)
			}
			store, err := openLoadBalanceStreamAccountStoreAt(path)
			if fault != "valid" {
				if err == nil {
					store.root.Close()
					t.Fatal("foreign/aliased/nonprivate store accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("original private store refused", err)
			}
			defer store.root.Close()
			held, err := store.read("account-intent.json")
			if err != nil || !bytes.Equal(held.bytes(), raw) || !held.current() {
				t.Fatal("original private held record refused", err)
			}
			defer held.close()
			if err := os.Rename(record, filepath.Join(parent, "held-original.json")); err != nil {
				t.Fatal(err)
			}
			write(record, raw, 0600)
			// A directory's metadata need not change at observable precision for
			// a same-name replacement. Its closed shape is not held-file identity.
			// Compare the actual inodes and require the held descriptor to refuse.
			originalInfo, e1 := held.(*loadBalanceStreamOSAccountRecord).file.Stat()
			visibleInfo, e2 := os.Lstat(record)
			if e1 != nil || e2 != nil || os.SameFile(originalInfo, visibleInfo) || held.current() {
				t.Fatal("same-byte replacement borrowed held original inode authority")
			}
			if err := store.writeExclusive("account-intent.json", raw); err == nil {
				t.Fatal("replacement allowed an existing original identity to be overwritten")
			}
			for _, file := range []string{record, filepath.Join(parent, "held-original.json")} {
				current, err := os.ReadFile(file)
				if err != nil || !bytes.Equal(current, raw) {
					t.Fatal("refused original/replacement operation changed existing bytes", err)
				}
			}
		})
	}
}

func TestLoadBalanceStreamAccountNativeCreationModelRetainsUncertainIntent(t *testing.T) {
	for _, fault := range []string{"success", "unknown-create", "receipt-write-failed", "revoked-after-create"} {
		t.Run(fault, func(t *testing.T) {
			path := streamAccountNativeFixture(t)
			store, err := openLoadBalanceStreamAccountStoreAt(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.root.Close()
			intent, identity := streamAccountFixture()
			creates, authorizes := 0, 0
			ops := loadBalanceStreamAccountOps{
				authorize: func(context.Context) error {
					authorizes++
					if fault == "revoked-after-create" && authorizes == 4 {
						return errLoadBalanceStreamAccount
					}
					return nil
				},
				absent: func(context.Context) error { return nil },
				// Deliberately a pure callback: no useradd/getent or /etc write.
				create: func(context.Context) error {
					creates++
					if fault == "unknown-create" {
						return errLoadBalanceStreamAccount
					}
					if fault == "receipt-write-failed" {
						return os.WriteFile(filepath.Join(path, "foreign.json"), []byte("foreign"), 0600)
					}
					return nil
				},
				resolve: func(context.Context) (loadBalanceStreamIdentity, error) { return identity, nil },
			}
			actual, err := prepareLoadBalanceStreamAccountAt(context.Background(), store, intent, ops)
			if creates != 1 || (fault == "success") != (err == nil) || (fault == "success") != (actual == identity) {
				t.Fatal("native private creation model outcome", actual, err, creates)
			}
			raw, err := os.ReadFile(filepath.Join(path, "account-intent.json"))
			if err != nil || !bytes.Equal(raw, loadBalanceStreamAccountBytes(intent)) {
				t.Fatal("original intent lost or overwritten", err)
			}
			if fault == "unknown-create" {
				if _, err := prepareLoadBalanceStreamAccountAt(context.Background(), store, intent, ops); err == nil || creates != 1 {
					t.Fatal("unknown native original intent was replayed")
				}
			}
			if fault == "success" || fault == "revoked-after-create" {
				body, err := os.ReadFile(filepath.Join(path, "account.json"))
				expected := loadBalanceStreamAccountBytes(loadBalanceStreamAccountReceipt{1, loadbalancestream.ServiceAccount, identity.UID, identity.GID, core.Hash(string(raw)), identity.SHA256})
				if err != nil || !bytes.Equal(body, expected) {
					t.Fatal("already-created exact ownership was removed or changed", err)
				}
			}
		})
	}
}

func TestLoadBalanceStreamAccountNativeHeldDirectoryReplacementRefuses(t *testing.T) {
	parent := streamAccountNativeFixture(t)
	path := filepath.Join(parent, "identity")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := openLoadBalanceStreamAccountStoreAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.root.Close()
	if err := os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	intent, _ := streamAccountFixture()
	if store.closed() || store.writeExclusive("account-intent.json", loadBalanceStreamAccountBytes(intent)) == nil {
		t.Fatal("replacement directory borrowed original held write authority")
	}
	for _, directory := range []string{path, path + "-original"} {
		values, err := os.ReadDir(directory)
		if err != nil || len(values) != 0 {
			t.Fatal("refused write changed original or replacement directory", err)
		}
	}
}

func TestLoadBalanceStreamAccountNativeReaderCannotInitializeFixedStore(t *testing.T) {
	_ = streamAccountNativeFixture(t)
	before, err := os.Lstat(loadBalanceStreamAccountStorePath)
	if !os.IsNotExist(err) || before != nil {
		t.Fatal("original fixed ownership anchor must be absent for this read-only case")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx, context.Background()} {
		if identity, err := loadBalanceStreamManagedSystemIdentity(ctx); err == nil || identity != (loadBalanceStreamIdentity{}) {
			t.Fatal("missing ownership produced a partial/borrowed identity")
		}
	}
	if info, err := os.Lstat(loadBalanceStreamAccountStorePath); !os.IsNotExist(err) || info != nil {
		t.Fatal("read-only missing ownership initialized a store")
	}
	for _, value := range []string{"/", "relative", strings.TrimSuffix(loadBalanceStreamAccountStorePath, "/") + "/../foreign"} {
		if store, err := openLoadBalanceStreamAccountStoreAt(value); err == nil || store != nil {
			t.Fatal("noncanonical/broad fixture root accepted", value)
		}
	}
}
