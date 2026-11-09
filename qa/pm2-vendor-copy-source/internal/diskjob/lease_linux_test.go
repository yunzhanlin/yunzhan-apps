//go:build linux

package diskjob

import (
	"errors"
	"os"
	"testing"
)

func TestHostJournalNativeLifecycleAndGlobalSlotNoStealing(t *testing.T) {
	tree := nativeJournalFixture(t)
	shared, err := treeLease(tree, "instance.lock", false)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	second, err := treeLease(tree, "instance.lock", false)
	if err != nil {
		t.Fatal("shared worker lease refused", err)
	}
	second.Close()
	if exclusive, err := treeLease(tree, "instance.lock", true); !errors.Is(err, ErrJournal) {
		if exclusive != nil {
			exclusive.Close()
		}
		t.Fatal("lifecycle writer stole live worker lease")
	}
	slot, err := treeLease(tree, "slot.lock", true)
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Close()
	if other, err := treeLease(tree, "slot.lock", true); !errors.Is(err, ErrJournal) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second worker stole global slot")
	}
	if _, err := treeLease(tree, "../outside", true); !errors.Is(err, ErrJournal) {
		t.Fatal("arbitrary lifecycle lock path accepted")
	}
	info, err := os.Lstat(tree.name + "/slot.lock")
	if err != nil || !journalInfo(info, false) || info.Size() != 0 {
		t.Fatal("global slot is not original private ordinary empty file")
	}
}
