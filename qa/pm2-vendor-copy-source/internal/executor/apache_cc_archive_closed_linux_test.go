//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func TestApacheCCArchiveUnstartedClosureRejectsDelayedOriginalDispatch(t *testing.T) {
	s, _, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
	ctx := context.Background()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	in := core.ApacheCCArchiveRequest{RequestID: core.ID(), ExpectedRevision: 7}
	closed, err := s.closeUnstartedApacheCCArchiveUnderLock(ctx, lock, in)
	if err != nil || closed.Request != in || closed.State != "closed-before-archive" {
		t.Fatal(closed, err)
	}
	before := programQueueTree(t, s.Config.SystemRoot)
	if _, err := s.archiveApacheCCLogRequestAt(ctx, in, nil); err == nil {
		t.Fatal("delayed original dispatch bypassed its closure tombstone")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("delayed original changed protected data")
	}
	again, err := s.closeUnstartedApacheCCArchiveUnderLock(ctx, lock, in)
	if err != nil || again != closed || !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("closure replay changed original bytes", again, err)
	}
	changed := in
	changed.ExpectedRevision++
	if _, err := s.closeUnstartedApacheCCArchiveUnderLock(ctx, lock, changed); err == nil {
		t.Fatal("closure adopted different original parameters")
	}
	lock.Close()
	if err := checkApacheNumericLogUpgrade(ctx, s.Config.SystemRoot); err != nil {
		t.Fatal("terminal closure blocked normal programme observation", err)
	}
}

func TestApacheCCArchiveClosureCannotHideStartedOrCorruptEvidence(t *testing.T) {
	for _, kind := range []string{"empty-directory", "prepared-durable", "names-exchanged", "corrupt-closure"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
			ctx := context.Background()
			in := core.ApacheCCArchiveRequest{RequestID: core.ID(), ExpectedRevision: 1, AllowIncomplete: true}
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			switch kind {
			case "empty-directory":
				if err := s.apacheNumericLogPrivateDirectory(s.apacheCCArchiveDirectory(), true); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(s.apacheCCArchiveDirectory(), in.RequestID), 0700); err != nil {
					t.Fatal(err)
				}
			case "corrupt-closure":
				if _, err := s.closeUnstartedApacheCCArchiveUnderLock(ctx, lock, in); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(s.apacheCCArchiveClosedDirectory(), in.RequestID+".json"), []byte("{\"format\":"), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				if _, err := s.archiveApacheCCLogRequestAt(ctx, in, func(stage string) error {
					if stage == kind {
						return errors.New("owned interruption")
					}
					return nil
				}); err == nil {
					t.Fatal("fault not reached")
				}
			}
			before := programQueueTree(t, s.Config.SystemRoot)
			if _, err := s.closeUnstartedApacheCCArchiveUnderLock(ctx, lock, in); err == nil {
				t.Fatal("started or corrupt original adopted as unstarted")
			}
			if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("closure refusal changed original evidence")
			}
		})
	}
}
