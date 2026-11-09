//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestFTPAccountLimitsFixedArgumentsAndPrivacy(t *testing.T) {
	in := core.AppModuleInput{QuotaMB: 10, QuotaFiles: 100, UploadKB: 8, DownloadKB: 16, MaxSessions: 2, ClientAllow: []string{"127.0.0.1", "192.0.2.123/24", "127.0.0.1"}, ClientDeny: []string{"198.51.100.0/24"}}
	limits, e := validatedFTPLimits(in)
	if e != nil {
		t.Fatal(e)
	}
	expected := []string{"-N", "10", "-n", "100", "-T", "8", "-t", "16", "-y", "2", "-r", "127.0.0.1,192.0.2.0/24", "-R", "198.51.100.0/24"}
	if !reflect.DeepEqual(limits.arguments(), expected) {
		t.Fatal(limits.arguments())
	}
	for _, bad := range []core.AppModuleInput{{QuotaMB: -1}, {QuotaFiles: 1000001}, {UploadKB: 1048577}, {MaxSessions: 21}, {ClientAllow: []string{"example.test"}}, {ClientDeny: []string{"127.0.0.1;id"}}, {ClientAllow: []string{"::1"}}, {ClientAllow: []string{"0.0.0.0"}}} {
		if _, e := validatedFTPLimits(bad); e == nil {
			t.Fatal("invalid limits accepted", bad)
		}
	}
	unlimited, _ := validatedFTPLimits(core.AppModuleInput{})
	if strings.Join(unlimited.arguments(), "|") != "-N||-n||-T||-t||-y||-r||-R|" {
		t.Fatal(unlimited.arguments())
	}
	line := "qa-user:never-return-this-hash:1234:33::/srv/panel/sites/abcdef0123456789abcdef0123456789/public/./:8192:16384:::2:100:10485760:::127.0.0.1:198.51.100.0/24:"
	users, e := ftpPublicUsers([]byte(line), "/srv/panel/sites")
	if e != nil {
		t.Fatal(e)
	}
	row := users[0]
	if row["quota_mb"] != 10 || row["upload_kb"] != 8 || row["download_kb"] != 16 || row["expected_sha"] != core.Hash(line) {
		t.Fatal(row)
	}
	b, _ := json.Marshal(users)
	if strings.Contains(string(b), "never-return-this-hash") {
		t.Fatal("password hash returned")
	}
}
func TestFTPAccountInterruptedCommitAndExternalModification(t *testing.T) {
	for _, phase := range []string{"old", "text-swapped", "both-swapped", "external", "committed"} {
		t.Run(phase, func(t *testing.T) {
			s, _ := ftpServiceFixture(t)
			dir := s.moduleDir("pure-ftpd")
			old := []byte("qa-user:old-private-hash:1234:33::/site/public/./:::::::::::::\n")
			next := []byte(strings.ReplaceAll(string(old), "old-private-hash", "new-private-hash"))
			oldDB, nextDB := []byte("original-index"), []byte("candidate-index")
			if phase == "text-swapped" || phase == "both-swapped" || phase == "committed" {
				atomicWrite(filepath.Join(dir, "users.passwd"), next, 0600)
			} else {
				atomicWrite(filepath.Join(dir, "users.passwd"), old, 0600)
			}
			if phase == "both-swapped" || phase == "committed" {
				atomicWrite(filepath.Join(dir, "users.pdb"), nextDB, 0600)
			} else {
				atomicWrite(filepath.Join(dir, "users.pdb"), oldDB, 0600)
			}
			txn := ftpAccountTransaction{ID: core.ID(), State: "applying", Username: "qa-user", OldText: old, OldDB: oldDB, NextTextSHA: core.Hash(string(next)), NextDBSHA: core.Hash(string(nextDB))}
			if phase == "external" {
				atomicWrite(filepath.Join(dir, "users.pdb"), []byte("outside-change"), 0600)
			}
			if phase == "committed" {
				txn.State = "committed"
			}
			if e := moduleWrite(filepath.Join(dir, "pending-accounts.json"), txn); e != nil {
				t.Fatal(e)
			}
			e := s.recoverFTPAccounts()
			text, _ := os.ReadFile(filepath.Join(dir, "users.passwd"))
			db, _ := os.ReadFile(filepath.Join(dir, "users.pdb"))
			if phase == "external" {
				if e == nil || string(db) != "outside-change" || !exists(filepath.Join(dir, "pending-accounts.json")) {
					t.Fatal("external data overwritten", e)
				}
				return
			}
			if e != nil || exists(filepath.Join(dir, "pending-accounts.json")) {
				t.Fatal(e)
			}
			if phase == "committed" {
				if !reflect.DeepEqual(text, next) || !reflect.DeepEqual(db, nextDB) {
					t.Fatal("committed state reverted")
				}
			} else if !reflect.DeepEqual(text, old) || !reflect.DeepEqual(db, oldDB) {
				t.Fatal("interrupted two-file commit not recovered")
			}
			info, e := os.Stat(filepath.Join(dir, "account-transactions", txn.ID+".json"))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("recovery backup not private", e)
			}
		})
	}
}
func TestFTPQuotaPinnedScanRejectsUnsafeEntriesAndLiveTransfers(t *testing.T) {
	f, site := fileFixture(t)
	public := filepath.Join(site, "public")
	os.Mkdir(filepath.Join(public, "folder"), 0755)
	os.WriteFile(filepath.Join(public, "a"), []byte("abc"), 0600)
	os.WriteFile(filepath.Join(public, "folder/b"), []byte("xyzzy"), 0600)
	outside := filepath.Join(t.TempDir(), "keep")
	os.WriteFile(outside, []byte("unrelated"), 0600)
	os.Symlink(outside, filepath.Join(public, "link"))
	scan := func(ctx context.Context) (uint64, uint64, error) {
		dir, e := f.public.Open(".")
		if e != nil {
			t.Fatal(e)
		}
		defer dir.Close()
		info, _ := dir.Stat()
		return scanFTPQuota(ctx, dir, uint64(info.Sys().(*syscall.Stat_t).Dev), 0)
	}
	count, size, e := scan(context.Background())
	if e != nil || count != 3 || size != 8 {
		t.Fatal(count, size, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e = scan(ctx); e == nil {
		t.Fatal("cancellation ignored")
	}
	os.Link(filepath.Join(public, "a"), filepath.Join(public, "hardlink"))
	if _, _, e = scan(context.Background()); e == nil {
		t.Fatal("hardlink accepted")
	}
	os.Remove(filepath.Join(public, "hardlink"))
	syscall.Mkfifo(filepath.Join(public, "pipe"), 0600)
	if _, _, e = scan(context.Background()); e == nil {
		t.Fatal("FIFO accepted")
	}
	os.Remove(filepath.Join(public, "pipe"))
	s, _ := ftpServiceFixture(t)
	if _, e = s.recountFTPQuota(context.Background(), f, "qa-user"); e == nil {
		t.Fatal("active transfers raced by recount")
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "inactive", nil }
	if _, e = s.recountFTPQuota(context.Background(), f, "qa-user"); e != nil {
		t.Fatal(e)
	}
	count, size, e = readFTPQuota(f)
	if e != nil || count != 3 || size != 8 {
		t.Fatal(count, size, e)
	}
	os.Remove(filepath.Join(public, ".ftpquota"))
	os.Symlink(outside, filepath.Join(public, ".ftpquota"))
	if _, e = s.recountFTPQuota(context.Background(), f, "qa-user"); e == nil {
		t.Fatal("counter symlink overwritten")
	}
	if data, _ := os.ReadFile(outside); string(data) != "unrelated" {
		t.Fatal("outside content changed")
	}
}
