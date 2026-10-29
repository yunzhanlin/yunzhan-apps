//go:build linux

package executor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func countryIdentityRecordFixture(t *testing.T) (string, *os.Root) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("private account-record filesystem regression requires Linux Root; it never changes NSS")
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return directory, root
}

func TestCountryNetworkIdentityRecordPrivateCreateAndNoReplacement(t *testing.T) {
	_, root := countryIdentityRecordFixture(t)
	identity := countryNetworkIdentity{1, 988, 982}
	if _, allowed := countryCacheFileLimit("country-network-account.json"); allowed {
		t.Fatal("account metadata widened the public cache filename authority")
	}
	if err := writeCountryNetworkIdentity(root, identity); err != nil {
		t.Fatal("first private account record was not persisted", err)
	}
	const name = "country-network-account.json"
	raw, err := root.ReadFile(name)
	expected, encodeErr := countryCacheJSON(identity)
	var parsed countryNetworkIdentity
	before, statErr := root.Lstat(name)
	if err != nil || encodeErr != nil || !bytes.Equal(raw, expected) || countryCacheDecode(raw, &parsed) != nil || parsed != identity || statErr != nil || !moduleRecordInfo(before, false, false) {
		t.Fatal("private original identity bytes or0600 Root ownership differ", err, statErr)
	}
	for _, next := range []countryNetworkIdentity{identity, {1, 989, 983}} {
		if err := writeCountryNetworkIdentity(root, next); !errors.Is(err, os.ErrExist) {
			t.Fatal("existing record was adopted or replaced", err)
		}
		after, err := root.Lstat(name)
		current, readErr := root.ReadFile(name)
		if err != nil || readErr != nil || !geoStoreStableInfo(before, after) || !bytes.Equal(current, raw) {
			t.Fatal("duplicate write changed the original evidence", err, readErr)
		}
	}
}

func TestCountryNetworkIdentityRecordRejectsInvalidAndWritableRoot(t *testing.T) {
	directory, root := countryIdentityRecordFixture(t)
	for _, identity := range []countryNetworkIdentity{{}, {2, 988, 982}, {1, 0, 982}, {1, 988, 0}, {1, 1000, 982}, {1, 988, 1000}} {
		if err := writeCountryNetworkIdentity(root, identity); err == nil {
			t.Fatal("invalid account identity created metadata", identity)
		}
	}
	if err := writeCountryNetworkIdentity(nil, countryNetworkIdentity{1, 988, 982}); err == nil {
		t.Fatal("missing module root was accepted")
	}
	if err := os.Chmod(directory, 0770); err != nil {
		t.Fatal(err)
	}
	if err := writeCountryNetworkIdentity(root, countryNetworkIdentity{1, 988, 982}); err == nil {
		t.Fatal("group-writable account-record directory was accepted")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected identity changed the directory", entries, err)
	}
}

func TestCountryNetworkIdentityRecordDoesNotFollowExistingLink(t *testing.T) {
	directory, root := countryIdentityRecordFixture(t)
	target := filepath.Join(t.TempDir(), "outside.json")
	const original = "retained outside evidence\n"
	if err := os.WriteFile(target, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "country-network-account.json")); err != nil {
		t.Fatal(err)
	}
	if err := writeCountryNetworkIdentity(root, countryNetworkIdentity{1, 988, 982}); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing symlink was followed or replaced", err)
	}
	raw, err := os.ReadFile(target)
	link, linkErr := root.Readlink("country-network-account.json")
	if err != nil || linkErr != nil || string(raw) != original || link != target {
		t.Fatal("outside bytes or original link changed", err, linkErr)
	}
}

func TestCountryNetworkIdentityRecordUsesTrustedServiceGroupDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0755, os.ModeSetgid | 0750} {
		t.Run(mode.String(), func(t *testing.T) {
			directory, root := countryIdentityRecordFixture(t)
			if err := os.Chown(directory, 0, 988); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, mode); err != nil {
				t.Fatal(err)
			}
			if err := countryNetworkIdentityDirectory(root); err != nil {
				t.Fatal("ordinary Root-owned, non-writable service-group directory rejected", err)
			}
			identity := countryNetworkIdentity{1, 987, 982}
			if err := writeCountryNetworkIdentity(root, identity); err != nil {
				t.Fatal("account record could not be created with actual module-directory metadata", err)
			}
			info, err := root.Lstat("country-network-account.json")
			raw, readErr := root.ReadFile("country-network-account.json")
			var actual countryNetworkIdentity
			if err != nil || !moduleRecordInfo(info, false, false) || readErr != nil || countryCacheDecode(raw, &actual) != nil || actual != identity {
				t.Fatal("record did not remain Root:Root0600 with original bytes", err, readErr)
			}
		})
	}
}
