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

func TestMemcachedUnixAdminPreparePrivateTransactionNeverAdoptsOrReplaysUnknownAccount(t *testing.T) {
	anchor := os.Getenv("PANEL_MEMCACHED_UNIX_ACCOUNT_QA_ROOT")
	if os.Geteuid() != 0 || anchor == "" {
		t.Skip("actual Root private filesystem fixture requires explicit own QA anchor")
	}
	if filepath.Clean(anchor) != anchor || !strings.HasPrefix(anchor, "/var/lib/panel-executor/memcached-unix-account-models") || threatIDSTrustedParents(anchor, false) != nil || !strings.HasPrefix(os.TempDir(), anchor+"/") {
		t.Fatal("private native anchor refused")
	}
	for _, scenario := range []string{"normal", "existing-intent", "orphan-receipt", "foreign-account", "create-failed", "resolve-failed", "root-uid", "root-gid", "non-system-uid", "non-system-gid", "changed-later-identity", "canceled-before", "canceled-after-create", "unknown-file", "hardlinked-intent", "duplicate-writer", "bad-record"} {
		t.Run(scenario, func(t *testing.T) {
			path := t.TempDir()
			store, err := openMemcachedUnixAdminStoreAt(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.root.Close()
			intent := memcachedUnixCanonicalRecord(memcachedUnixAdminIntent{1, memcachedUnixAdminName, strings.Repeat("a", 32)})
			switch scenario {
			case "existing-intent", "hardlinked-intent":
				if err = store.writeExclusiveRecord("admin-intent.json", intent); err != nil {
					t.Fatal(err)
				}
				if scenario == "hardlinked-intent" && os.Link(filepath.Join(path, "admin-intent.json"), filepath.Join(path, "other-link")) != nil {
					t.Fatal("hardlink fixture")
				}
			case "orphan-receipt":
				raw := memcachedUnixCanonicalRecord(memcachedUnixAdminReceipt{1, memcachedUnixAdminName, 800, 801, strings.Repeat("b", 64)})
				if err = store.writeExclusiveRecord("admin.json", raw); err != nil {
					t.Fatal(err)
				}
			case "unknown-file":
				if os.WriteFile(filepath.Join(path, "unmanaged"), []byte("own fixture"), 0600) != nil {
					t.Fatal("unknown own fixture")
				}
			case "duplicate-writer":
				if err = store.writeExclusiveRecord("admin-intent.json", intent); err != nil {
					t.Fatal(err)
				}
				held, body, e := store.openRecord("admin-intent.json")
				if e != nil {
					t.Fatal(e)
				}
				defer held.file.Close()
				if store.writeExclusiveRecord("admin-intent.json", intent) == nil || !held.current() {
					t.Fatal("exclusive writer overwrote or changed original inode")
				}
				after, e := os.ReadFile(filepath.Join(path, "admin-intent.json"))
				if e != nil || string(body) != string(after) {
					t.Fatal("original intent changed")
				}
				return
			case "bad-record":
				if store.writeExclusiveRecord("admin.json", []byte("{}\n")) == nil {
					t.Fatal("invalid record published")
				}
				if _, err = os.Lstat(filepath.Join(path, "admin.json")); !os.IsNotExist(err) {
					t.Fatal("invalid write created a target")
				}
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled-before" {
				cancel()
			}
			absent, creates, resolves := 0, 0, 0
			ops := memcachedUnixAdminPrepareOps{
				absent: func(context.Context) error {
					absent++
					if scenario == "foreign-account" {
						return errors.New("own simulated pre-existing account")
					}
					return nil
				},
				create: func(context.Context) error {
					creates++
					if scenario == "create-failed" {
						return errors.New("own simulated useradd partial failure")
					}
					if scenario == "canceled-after-create" {
						cancel()
					}
					return nil
				},
				resolve: func(context.Context) (memcachedUnixAccount, error) {
					resolves++
					a := memcachedUnixAccount{800, 801}
					switch scenario {
					case "resolve-failed":
						return memcachedUnixAccount{}, errors.New("own simulated lookup failure")
					case "root-uid":
						a.UID = 0
					case "root-gid":
						a.GID = 0
					case "non-system-uid":
						a.UID = 1000
					case "non-system-gid":
						a.GID = 1000
					case "changed-later-identity":
						if resolves > 1 {
							a.UID = 802
						}
					}
					return a, nil
				},
			}
			err = prepareMemcachedUnixAdminAt(ctx, store, ops)
			if scenario == "normal" {
				if err != nil || absent != 1 || creates != 1 || resolves != 2 {
					t.Fatal("own simulated first creation", err, absent, creates, resolves)
				}
				f, original, e := store.openRecord("admin.json")
				if e != nil {
					t.Fatal(e)
				}
				defer f.file.Close()
				if _, e = decodeMemcachedUnixAdminReceipt(original); e != nil {
					t.Fatal(e)
				}
				if e = prepareMemcachedUnixAdminAt(ctx, store, ops); e != nil || absent != 1 || creates != 1 || resolves != 3 || !f.current() {
					t.Fatal("completed ownership was re-created or changed", e, absent, creates, resolves)
				}
				return
			}
			if err == nil {
				t.Fatal("incomplete/unowned/expired state accepted", scenario)
			}
			switch scenario {
			case "existing-intent", "orphan-receipt", "foreign-account", "canceled-before", "unknown-file", "hardlinked-intent":
				if creates != 0 {
					t.Fatal("refused state reached account creation")
				}
			default:
				if absent != 1 || creates != 1 {
					t.Fatal("original creation was not single", absent, creates)
				}
				intentFile, e := os.ReadFile(filepath.Join(path, "admin-intent.json"))
				if e != nil {
					t.Fatal("original intent not retained", e)
				}
				if _, e = decodeMemcachedUnixAdminIntent(intentFile); e != nil {
					t.Fatal(e)
				}
				beforeCount := creates
				if e = prepareMemcachedUnixAdminAt(context.Background(), store, ops); e == nil || creates != beforeCount {
					t.Fatal("unknown outcome was adopted or replayed", e, creates)
				}
			}
		})
	}
}
