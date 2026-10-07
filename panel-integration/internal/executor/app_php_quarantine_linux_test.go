//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func phpQuarantineFixture(t *testing.T) (*Service, core.AppModuleInput, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root Linux executor acceptance")
	}
	_, site := fileFixture(t)
	id := filepath.Base(site)
	public := filepath.Join(site, "public")
	if err := os.Chown(public, 54321, 54321); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(public, "app"), 0755); err != nil {
		t.Fatal(err)
	}
	os.Chown(filepath.Join(public, "app"), 54321, 54321)
	data := []byte("<?php /* legitimate but risky sample */ eval('return 1;'); echo 'qa-php';\n")
	path := filepath.Join(public, "app/risk.php")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 54321, 54321); err != nil {
		t.Fatal(err)
	}
	s := New(Config{SitesDir: filepath.Dir(site), SecurityDir: t.TempDir(), StateDir: t.TempDir(), Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("quarantine must not control services")
		return "", nil
	}})
	in := core.AppModuleInput{SiteID: id, Path: "app/risk.php", ExpectedSHA: phpSHA(data), Confirm: "QUARANTINE app/risk.php"}
	return s, in, site
}

func phpTestRecord(t *testing.T, s *Service, in core.AppModuleInput) phpQuarantineRecord {
	t.Helper()
	v, err := s.modulePHPQuarantine(context.Background(), "quarantine", in)
	if err != nil {
		t.Fatal(err)
	}
	q, err := s.phpReadQuarantine(v.(map[string]any)["record"].(map[string]any)["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func phpTestRestoreInput(q phpQuarantineRecord, recover bool) core.AppModuleInput {
	confirm := "RESTORE PHP " + q.ID
	if recover {
		confirm = "RECOVER PHP " + q.ID
	}
	return core.AppModuleInput{SiteID: q.SiteID, Path: q.Path, ExpectedSHA: q.SHA256, ResourceID: q.ID, ExpectedRevision: q.Revision, Confirm: confirm}
}

func TestPHPQuarantineAndNoOverwriteRestorePreserveEvidence(t *testing.T) {
	s, in, site := phpQuarantineFixture(t)
	path := filepath.Join(site, "public", in.Path)
	if err := unix.Setxattr(path, "user.qa-php", []byte("attribute-evidence"), 0); err != nil {
		t.Fatal(err)
	}
	oldFD, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer oldFD.Close()
	q := phpTestRecord(t, s, in)
	if q.State != "quarantined" || q.Revision != 2 {
		t.Fatal(q)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("source remains public", err)
	}
	storage := filepath.Join(site, filePrivate, "php-quarantine", q.ID)
	for _, name := range []string{"backup.bin", "moved.bin"} {
		st, err := os.Stat(filepath.Join(storage, name))
		if err != nil {
			t.Fatal(err)
		}
		identity := st.Sys().(*syscall.Stat_t)
		if identity.Uid != 0 || identity.Gid != 0 || st.Mode().Perm() != 0600 {
			t.Fatal("private file permissions", st)
		}
	}
	// Already-open write descriptors survive chown/rename; the separate reviewed
	// copy must remain usable, rather than promising runtime process interception.
	if _, err = oldFD.WriteAt([]byte("changed-after-isolation"), 0); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(filepath.Join(storage, "backup.bin"))
	if err != nil || phpSHA(backup) != in.ExpectedSHA {
		t.Fatal("independent backup changed", err)
	}
	if err = os.WriteFile(path, []byte("new-public-version"), 0644); err != nil {
		t.Fatal(err)
	}
	os.Chown(path, 54321, 54321)
	if _, err = s.modulePHPQuarantine(context.Background(), "restore-quarantine", phpTestRestoreInput(q, false)); err == nil {
		t.Fatal("overwrote replacement")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new-public-version" {
		t.Fatal("replacement altered")
	}
	if err = os.Rename(path, filepath.Join(site, "public/app/replacement-retained.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.modulePHPQuarantine(context.Background(), "restore-quarantine", phpTestRestoreInput(q, false)); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if !bytes.Equal(data, backup) {
		t.Fatal("restoration did not use reviewed backup")
	}
	info, _ := os.Stat(path)
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != 54321 || st.Gid != 54321 || info.Mode().Perm() != 0640 {
		t.Fatal("ownership or mode lost", st, info.Mode())
	}
	x := make([]byte, 64)
	n, err := unix.Getxattr(path, "user.qa-php", x)
	if err != nil || string(x[:n]) != "attribute-evidence" {
		t.Fatal("attributes lost", err)
	}
	if _, err = os.Stat(filepath.Join(storage, "backup.bin")); err != nil {
		t.Fatal("backup removed")
	}
	q, err = s.phpReadQuarantine(q.ID)
	if err != nil || q.State != "restored" {
		t.Fatal(q, err)
	}
	if err = s.phpQuarantineReference(in.SiteID); err != nil {
		t.Fatal(err)
	}
}

func TestPHPQuarantineRejectsStaleAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"stale", "confirm", "not-php", "escape", "symlink", "parent-symlink", "hardlink", "fifo", "owner", "mode", "oversized", "private-symlink", "capability"} {
		t.Run(kind, func(t *testing.T) {
			s, in, site := phpQuarantineFixture(t)
			path := filepath.Join(site, "public", in.Path)
			before, _ := os.ReadFile(path)
			switch kind {
			case "stale":
				in.ExpectedSHA = strings.Repeat("0", 64)
			case "confirm":
				in.Confirm = "yes"
			case "not-php":
				in.Path = "app/risk.txt"
				in.Confirm = "QUARANTINE " + in.Path
			case "escape":
				in.Path = "../app/risk.php"
				in.Confirm = "QUARANTINE " + in.Path
			case "symlink":
				os.Rename(path, path+".retained")
				os.Symlink(path+".retained", path)
			case "parent-symlink":
				os.Rename(filepath.Join(site, "public/app"), filepath.Join(site, "public/retained-app"))
				os.Symlink("retained-app", filepath.Join(site, "public/app"))
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				os.Rename(path, path+".retained")
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "owner":
				os.Chown(path, 0, 0)
			case "mode":
				os.Chmod(path, os.ModeSetuid|0755)
			case "oversized":
				f, _ := os.OpenFile(path, os.O_WRONLY, 0)
				f.Truncate(phpQuarantineMaxFile + 1)
				f.Close()
			case "private-symlink":
				os.Symlink(t.TempDir(), filepath.Join(site, filePrivate))
			case "capability":
				cap := make([]byte, 20)
				cap[3] = 2
				cap[4] = 1
				if err := unix.Setxattr(path, "security.capability", cap, 0); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.modulePHPQuarantine(context.Background(), "quarantine", in); err == nil {
				t.Fatal("unsafe source accepted", kind)
			}
			if kind != "fifo" && kind != "oversized" {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("rejected operation altered source", err)
				}
			}
		})
	}
}

func TestPHPQuarantinePreparedRecoveryAndCommitConflict(t *testing.T) {
	for _, phase := range []string{"before-move", "after-move", "before-backup", "replacement-before-commit", "replacement-after-move"} {
		t.Run(phase, func(t *testing.T) {
			s, in, site := phpQuarantineFixture(t)
			q, f, err := s.phpPrepareQuarantine(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "before-backup" {
				f.storage.Close()
				f.storage = nil
				os.Rename(filepath.Join(site, filePrivate), filepath.Join(site, "private-preparation-retained"))
			}
			if phase == "after-move" || phase == "replacement-after-move" {
				if err = phpRenameNoReplace(f.parent, filepath.Base(q.Path), f.storage, "moved.bin"); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(phase, "replacement") {
				path := filepath.Join(site, "public", in.Path)
				if phase == "replacement-before-commit" {
					os.Rename(path, path+".reviewed-retained")
				}
				os.WriteFile(path, []byte("replacement-version"), 0644)
				os.Chown(path, 54321, 54321)
			}
			if phase == "replacement-before-commit" {
				if err = s.phpFinishQuarantine(&q, f); err == nil || q.State != "cancelled" {
					t.Fatal(q, err)
				}
				f.Close()
				return
			}
			f.Close()
			if _, err = s.modulePHPQuarantine(context.Background(), "recover-quarantine", phpTestRestoreInput(q, true)); err != nil {
				t.Fatal(err)
			}
			q, err = s.phpReadQuarantine(q.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := "cancelled"
			if phase == "after-move" || phase == "replacement-after-move" {
				want = "quarantined"
			}
			if q.State != want {
				t.Fatal(q.State, want)
			}
			if phase == "replacement-after-move" {
				data, _ := os.ReadFile(filepath.Join(site, "public", in.Path))
				if string(data) != "replacement-version" {
					t.Fatal("new file overwritten")
				}
				r, err := s.phpListQuarantine(core.AppModuleInput{})
				if err != nil || r.(map[string]any)["quarantine"].([]map[string]any)[0]["source_present"] != true {
					t.Fatal(r, err)
				}
			}
		})
	}
}

func TestPHPQuarantineRestoreRecoveryAcrossStageAndPublish(t *testing.T) {
	for _, phase := range []string{"before-stage", "partial-stage", "after-stage", "after-publish", "publish-conflict"} {
		t.Run(phase, func(t *testing.T) {
			s, in, site := phpQuarantineFixture(t)
			q := phpTestRecord(t, s, in)
			q.StageID = core.ID()
			if err := s.phpSaveQuarantine(&q, "restoring"); err != nil {
				t.Fatal(err)
			}
			f, err := s.phpQuarantineFiles(&q, false)
			if err != nil {
				t.Fatal(err)
			}
			stageName := "restore-" + q.StageID + ".bin"
			if phase == "partial-stage" {
				stage, err := phpWritePrivate(f.storage, stageName, []byte("partial"))
				if err != nil {
					t.Fatal(err)
				}
				stage.Close()
			}
			if phase == "after-stage" || phase == "after-publish" || phase == "publish-conflict" {
				data, _, _ := phpReadFile(f.storage, "backup.bin", true)
				stage, err := phpWritePrivate(f.storage, stageName, data)
				if err != nil {
					t.Fatal(err)
				}
				stage.Chown(q.UID, q.GID)
				stage.Chmod(os.FileMode(q.Mode))
				stage.Sync()
				info, _ := stage.Stat()
				q.Restored = phpIdentity(info)
				stage.Close()
				if err = s.phpSaveQuarantine(&q, "restoring"); err != nil {
					t.Fatal(err)
				}
				if phase == "after-publish" {
					if err = phpRenameNoReplace(f.storage, stageName, f.parent, filepath.Base(q.Path)); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "publish-conflict" {
					os.WriteFile(filepath.Join(site, "public", in.Path), []byte("concurrent-original-location"), 0644)
				}
			}
			f.Close()
			_, err = s.modulePHPQuarantine(context.Background(), "recover-quarantine", phpTestRestoreInput(q, true))
			if phase == "publish-conflict" {
				if err == nil {
					t.Fatal("conflicting target adopted")
				}
				data, _ := os.ReadFile(filepath.Join(site, "public", in.Path))
				if string(data) != "concurrent-original-location" {
					t.Fatal("conflicting target changed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(filepath.Join(site, "public", in.Path))
			if phpSHA(data) != in.ExpectedSHA {
				t.Fatal("wrong content after recovery")
			}
			q, err = s.phpReadQuarantine(q.ID)
			if err != nil || q.State != "restored" {
				t.Fatal(q, err)
			}
		})
	}
}

func TestPHPQuarantineDamagedBackupDirectoryAndRevisionFailClosed(t *testing.T) {
	for _, kind := range []string{"backup", "backup-mode", "revision", "digest", "record", "parent", "site", "module-uninstall", "site-archive"} {
		t.Run(kind, func(t *testing.T) {
			s, in, site := phpQuarantineFixture(t)
			q := phpTestRecord(t, s, in)
			restore := phpTestRestoreInput(q, false)
			switch kind {
			case "backup":
				os.WriteFile(filepath.Join(site, filePrivate, "php-quarantine", q.ID, "backup.bin"), []byte("corrupted"), 0600)
			case "backup-mode":
				os.Chmod(filepath.Join(site, filePrivate, "php-quarantine", q.ID, "backup.bin"), 0644)
			case "revision":
				restore.ExpectedRevision--
			case "digest":
				restore.ExpectedSHA = strings.Repeat("a", 64)
			case "record":
				os.Chmod(filepath.Join(s.moduleDir(phpQuarantineModule), "quarantine", q.ID+".json"), 0644)
			case "parent":
				os.Rename(filepath.Join(site, "public/app"), filepath.Join(site, "public/retained-app"))
				os.Mkdir(filepath.Join(site, "public/app"), 0755)
				os.Chown(filepath.Join(site, "public/app"), 54321, 54321)
			case "site":
				os.Rename(site, site+".retained")
				os.MkdirAll(filepath.Join(site, "public/app"), 0755)
				os.Chown(filepath.Join(site, "public"), 54321, 54321)
				marker, _ := json.Marshal(map[string]string{"id": in.SiteID})
				os.WriteFile(filepath.Join(site, ".panel-site.json"), marker, 0600)
			}
			var err error
			if kind == "module-uninstall" {
				moduleWrite(filepath.Join(s.moduleDir(phpQuarantineModule), "installed.json"), map[string]string{"id": phpQuarantineModule})
				err = s.appModuleLifecycle(context.Background(), phpQuarantineModule, "uninstall", nil, func(string) {})
				if !s.moduleInstalled(phpQuarantineModule) {
					t.Fatal("uninstalled with live quarantine")
				}
			} else if kind == "site-archive" {
				err = s.phpQuarantineReference(in.SiteID)
			} else {
				_, err = s.modulePHPQuarantine(context.Background(), "restore-quarantine", restore)
			}
			if err == nil {
				t.Fatal("unsafe restore/lifecycle accepted", kind)
			}
			if _, err = os.Lstat(filepath.Join(site, "public", in.Path)); !os.IsNotExist(err) {
				t.Fatal("rejected workflow republished original", err)
			}
		})
	}
}

func TestPHPQuarantineRecordBudgetPaginationAndRedaction(t *testing.T) {
	s, in, site := phpQuarantineFixture(t)
	q := phpTestRecord(t, s, in)
	if err := s.phpSaveQuarantine(&q, "cancelled"); err != nil {
		t.Fatal(err)
	}
	backup, _ := os.ReadFile(filepath.Join(site, filePrivate, "php-quarantine", q.ID, "backup.bin"))
	os.WriteFile(filepath.Join(site, "public", in.Path), backup, 0640)
	os.Chown(filepath.Join(site, "public", in.Path), 54321, 54321)
	for i := 0; i < 32; i++ {
		copy := q
		copy.ID = core.ID()
		copy.Bytes = phpQuarantineMaxFile
		copy.Path = fmt.Sprintf("app/budget-%d.php", i)
		copy.Revision = 0
		if err := s.phpSaveQuarantine(&copy, "cancelled"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.modulePHPQuarantine(context.Background(), "quarantine", in); err == nil || !strings.Contains(err.Error(), "256 MiB") {
		t.Fatal("backup budget ignored")
	}
	r, err := s.phpListQuarantine(core.AppModuleInput{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.(map[string]any)["total"] != 33 || len(r.(map[string]any)["quarantine"].([]map[string]any)) != 2 {
		t.Fatal(r)
	}
	data, _ := json.Marshal(r)
	for _, secret := range []string{"attributes", "attribute-evidence", "original_identity", "backup.bin", "<?php"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("private data exposed", secret)
		}
	}
	for _, invalid := range []core.AppModuleInput{{Limit: 201}, {Offset: -1}, {SiteID: "../escape"}, {Search: strings.Repeat("x", 129)}} {
		if _, err := s.phpListQuarantine(invalid); err == nil {
			t.Fatal("invalid filter accepted")
		}
	}
}

func TestPHPQuarantineExecutorPrimaryGroupDoesNotWeakenPrivacy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if os.Getenv("PANEL_TEST_PHP_NONROOT_GROUP") == "1" {
		s, in, _ := phpQuarantineFixture(t)
		q := phpTestRecord(t, s, in)
		if _, err := s.modulePHPQuarantine(context.Background(), "restore-quarantine", phpTestRestoreInput(q, false)); err != nil {
			t.Fatal(err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPHPQuarantineExecutorPrimaryGroupDoesNotWeakenPrivacy$", "-test.v")
	cmd.Env = append(os.Environ(), "PANEL_TEST_PHP_NONROOT_GROUP=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: 54322}}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
}

func TestPHPQuarantineRecordCountAndCrossFilesystemAreBounded(t *testing.T) {
	t.Run("record-count", func(t *testing.T) {
		s, in, _ := phpQuarantineFixture(t)
		q := phpTestRecord(t, s, in)
		q.Bytes = 0
		if err := s.phpSaveQuarantine(&q, "cancelled"); err != nil {
			t.Fatal(err)
		}
		for i := 1; i < phpQuarantineMaxRecords; i++ {
			copy := q
			copy.ID = core.ID()
			copy.Path = fmt.Sprintf("app/record-%d.php", i)
			copy.Revision = 0
			if err := s.phpSaveQuarantine(&copy, "cancelled"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.modulePHPQuarantine(context.Background(), "quarantine", in); err == nil || !strings.Contains(err.Error(), "512") {
			t.Fatal("record budget not enforced", err)
		}
	})
	t.Run("cross-filesystem", func(t *testing.T) {
		s, in, site := phpQuarantineFixture(t)
		mount := filepath.Join(site, "public/mounted")
		if err := os.Mkdir(mount, 0755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount("tmpfs", mount, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=16m"); err == unix.EPERM {
			t.Skip("isolated mount capability not available")
		} else if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := unix.Unmount(mount, 0); err != nil {
				t.Error(err)
			}
		}()
		os.Chown(mount, 54321, 54321)
		data := []byte("<?php echo 'safe';")
		path := filepath.Join(mount, "risk.php")
		os.WriteFile(path, data, 0640)
		os.Chown(path, 54321, 54321)
		in.Path = "mounted/risk.php"
		in.ExpectedSHA = phpSHA(data)
		in.Confirm = "QUARANTINE " + in.Path
		if _, err := s.modulePHPQuarantine(context.Background(), "quarantine", in); err == nil || !strings.Contains(err.Error(), "跨文件系统") {
			t.Fatal("cross-filesystem move allowed", err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(data, after) {
			t.Fatal("mounted source changed")
		}
		rows, err := s.phpQuarantineRecords()
		if err != nil || len(rows) != 0 {
			t.Fatal("rejected mount allocated a transaction", rows, err)
		}
	})
}
