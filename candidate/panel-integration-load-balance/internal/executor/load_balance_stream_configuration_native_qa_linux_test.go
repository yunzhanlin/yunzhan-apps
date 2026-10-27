//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamConfigurationNativeFixture(t *testing.T, seedRaw []byte) (*loadBalanceStreamConfigurationFile, string) {
	t.Helper()
	root, path, _ := streamGenerationNativeRoot(t)
	// A private filesystem model only. No NSS identity is created/adopted and
	// no actual service or host configuration directory is touched.
	if err := os.Chown(path, 0, 991); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0750); err != nil {
		t.Fatal(err)
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed.Before) > 0 {
		configuration, err := loadbalancestream.RenderRuntime(seed.Before, loadbalancestream.ServiceRuntimePrefix, loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget})
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(path, "nginx.conf")
		if err := os.WriteFile(file, configuration.Main, 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(file, 0, 991); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, 0640); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := root.Stat(".")
	current := func() bool {
		held, e1 := root.Stat(".")
		visible, e2 := os.Lstat(path)
		return e1 == nil && e2 == nil && streamConfigurationInfo(held, 991, true) && os.SameFile(before, held) && os.SameFile(held, visible)
	}
	f, err := holdStreamConfigurationAt(root, 991, current)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.close)
	return f, path
}

func TestLoadBalanceStreamConfigurationNativeStageAndAtomicPromotionKeepReadableOwnedOldInode(t *testing.T) {
	for _, update := range []bool{false, true} {
		t.Run(map[bool]string{false: "first", true: "update"}[update], func(t *testing.T) {
			seed := streamJournalNativeSeed(t)
			if update {
				seed = streamGenerationNativeNext(t, seed)
			}
			original, path := streamConfigurationNativeFixture(t, seed)
			publication, pubPath, current := streamGenerationNativeRoot(t)
			p, err := stageStreamConfigurationAt(context.Background(), publication, current, original, seed, streamModuleModelAuthorize)
			if err != nil || !p.candidateCurrent() || !original.current() {
				t.Fatal("actual private candidate/old original refused", err)
			}
			defer p.close()
			staged, err := original.root.Lstat(".candidate-" + p.request + ".conf")
			if err != nil || !streamConfigurationInfo(staged, 991, false) {
				t.Fatal("service can write candidate or cannot read it", err)
			}
			if update {
				raw, err := os.ReadFile(filepath.Join(pubPath, "original.json"))
				if err != nil || !bytes.Equal(raw, original.raw) {
					t.Fatal("complete old backup missing", err)
				}
			}
			if q, err := stageStreamConfigurationAt(context.Background(), publication, current, original, seed, streamModuleModelAuthorize); err == nil || q != nil {
				t.Fatal("old publication was adopted")
			}
			digest, err := p.promoteAt(context.Background(), streamModuleModelAuthorize)
			if err != nil || digest != core.Hash(string(p.proposal)) || !p.attempted || !p.promoted {
				t.Fatal("original atomic configuration promotion refused", err)
			}
			body, err := os.ReadFile(filepath.Join(path, "nginx.conf"))
			if err != nil || !bytes.Equal(body, p.proposal) {
				t.Fatal("new configuration bytes changed", err)
			}
			if _, err := p.promoteAt(context.Background(), streamModuleModelAuthorize); err == nil {
				t.Fatal("promotion replayed")
			}
			if update {
				old, err := original.root.Lstat(".candidate-" + p.request + ".conf")
				if err != nil || !os.SameFile(old, original.before) || !streamConfigurationInfo(old, 991, false) {
					t.Fatal("actual old inode/ownership/mode lost", err)
				}
			}
		})
	}
}

func TestLoadBalanceStreamConfigurationNativeCandidateDriftAndUnknownOutcomeNeverRestoreOrRetry(t *testing.T) {
	for _, fault := range []string{"candidate-bytes", "candidate-mode", "old-drift", "extra-metadata", "revoked-after-exchange"} {
		t.Run(fault, func(t *testing.T) {
			seed := streamGenerationNativeNext(t, streamJournalNativeSeed(t))
			original, path := streamConfigurationNativeFixture(t, seed)
			publication, pubPath, current := streamGenerationNativeRoot(t)
			p, err := stageStreamConfigurationAt(context.Background(), publication, current, original, seed, streamModuleModelAuthorize)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			candidate := filepath.Join(path, ".candidate-"+p.request+".conf")
			authorize := streamModuleModelAuthorize
			switch fault {
			case "candidate-bytes":
				if err := os.WriteFile(candidate, []byte("changed\n"), 0640); err != nil {
					t.Fatal(err)
				}
			case "candidate-mode":
				if err := os.Chmod(candidate, 0660); err != nil {
					t.Fatal(err)
				}
			case "old-drift":
				if err := os.WriteFile(filepath.Join(path, "nginx.conf"), []byte("foreign\n"), 0640); err != nil {
					t.Fatal(err)
				}
			case "extra-metadata":
				if err := os.WriteFile(filepath.Join(pubPath, "unknown.json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "revoked-after-exchange":
				authorize = func(context.Context) error {
					info, err := os.Lstat(filepath.Join(path, "nginx.conf"))
					if err == nil && os.SameFile(info, p.candidateBefore) {
						return errors.New("revoked after actual exchange")
					}
					return nil
				}
			}
			if _, err := p.promoteAt(context.Background(), authorize); err == nil || p.promoted {
				t.Fatal("drift/unknown was relabelled a promoted configuration", err)
			}
			before, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatal("uncertain original inode lost", err)
			}
			if _, err := p.promoteAt(context.Background(), streamModuleModelAuthorize); err == nil {
				t.Fatal("uncertain/refused promotion replayed")
			}
			after, err := os.ReadFile(candidate)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("unknown/refused original was restored, rewritten or removed", err)
			}
			if fault == "revoked-after-exchange" && !p.attempted {
				t.Fatal("lost original attempt witness")
			}
		})
	}
}

func TestLoadBalanceStreamOwnedConfigurationMissingOriginalPhaseCannotTouchHostPaths(t *testing.T) {
	if raw, err := (*loadBalanceStreamControlOwner)(nil).configurationPhase(context.Background(), "activation-intent"); err == nil || raw != nil {
		t.Fatal("missing original phase accepted")
	}
	if p, err := stageLoadBalanceStreamOwnedConfigurationAt(context.Background(), nil, nil, nil, nil); err == nil || p != nil {
		t.Fatal("missing original writer reached host configuration")
	}
	if _, err := (&loadBalanceStreamConfigurationPublication{}).promoteOwned(context.Background(), nil); err == nil {
		t.Fatal("claimed publication reached host promotion")
	}
}
