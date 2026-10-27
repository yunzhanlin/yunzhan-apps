//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBalanceStreamConfigurationNativeReceiptRequiresOriginalStageAndActualPromotion(t *testing.T) {
	for _, update := range []bool{false, true} {
		t.Run(map[bool]string{false: "first", true: "update"}[update], func(t *testing.T) {
			seed := streamJournalNativeSeed(t)
			if update {
				seed = streamGenerationNativeNext(t, seed)
			}
			original, _ := streamConfigurationNativeFixture(t, seed)
			pub, _, current := streamGenerationNativeRoot(t)
			p, err := stageStreamConfigurationAt(context.Background(), pub, current, original, seed, streamModuleModelAuthorize)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			staged, err := decodeStreamConfigurationFileReceipt(p.stagedReceipt)
			if err != nil || staged.Phase != "staged" {
				t.Fatal("actual original staged inode receipt refused", err)
			}
			if _, err := checkStreamConfigurationPublication(pub, original.root, seed, 991, true); err == nil {
				t.Fatal("staged bytes became a promoted/current configuration")
			}
			if _, err := p.promoteAt(context.Background(), streamModuleModelAuthorize); err != nil {
				t.Fatal(err)
			}
			history, err := checkStreamConfigurationPublication(pub, original.root, seed, 991, true)
			if err != nil || history.Promoted.Phase != "promoted" || !bytes.Equal(history.Proposal, p.proposal) || !streamConfigurationSameRenameIdentity(history.Staged.File, history.Promoted.File) {
				t.Fatal("actual original promotion/inode/closed metadata refused", err)
			}
			if history.Intent.Original.Exists != update {
				t.Fatal("original first/update boundary changed")
			}
		})
	}
}

func TestLoadBalanceStreamConfigurationNativeReceiptCopiesAndAmbiguityCannotAdoptOriginal(t *testing.T) {
	for _, fault := range []string{"copied-current-inode", "copied-old-inode", "missing-stage", "duplicate-stage-field", "missing-promotion", "changed-promotion", "extra-file"} {
		t.Run(fault, func(t *testing.T) {
			seed := streamGenerationNativeNext(t, streamJournalNativeSeed(t))
			original, path := streamConfigurationNativeFixture(t, seed)
			pub, pubPath, current := streamGenerationNativeRoot(t)
			p, err := stageStreamConfigurationAt(context.Background(), pub, current, original, seed, streamModuleModelAuthorize)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			if _, err := p.promoteAt(context.Background(), streamModuleModelAuthorize); err != nil {
				t.Fatal(err)
			}
			if _, err := checkStreamConfigurationPublication(pub, original.root, seed, 991, true); err != nil {
				t.Fatal("valid original fixture refused", err)
			}
			switch fault {
			case "copied-current-inode", "copied-old-inode":
				name := "nginx.conf"
				raw := p.proposal
				if fault == "copied-old-inode" {
					name = ".candidate-" + p.request + ".conf"
					raw = original.raw
				}
				before, err := os.Lstat(filepath.Join(path, name))
				if err != nil {
					t.Fatal(err)
				}
				copy := filepath.Join(path, "model-copy.conf")
				if err := os.WriteFile(copy, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(copy, 0, 991); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(copy, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(copy, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(copy, filepath.Join(path, name)); err != nil {
					t.Fatal(err)
				}
			case "missing-stage":
				if err := os.Remove(filepath.Join(pubPath, "staged.json")); err != nil {
					t.Fatal(err)
				}
			case "duplicate-stage-field":
				raw := bytes.Replace(p.stagedReceipt, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1)
				if err := os.WriteFile(filepath.Join(pubPath, "staged.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-promotion":
				if err := os.Remove(filepath.Join(pubPath, "promoted.json")); err != nil {
					t.Fatal(err)
				}
			case "changed-promotion":
				raw := bytes.Replace(p.promotedReceipt, []byte(`"phase":"promoted"`), []byte(`"phase":"staged"`), 1)
				if err := os.WriteFile(filepath.Join(pubPath, "promoted.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-file":
				if err := os.WriteFile(filepath.Join(pubPath, "unexpected.json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := checkStreamConfigurationPublication(pub, original.root, seed, 991, true); err == nil {
				t.Fatal("copied/missing/ambiguous original receipt became valid", fault)
			}
		})
	}
}
