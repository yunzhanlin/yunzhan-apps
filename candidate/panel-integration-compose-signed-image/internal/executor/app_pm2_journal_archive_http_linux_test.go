//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPM2JournalReadLeaseNeverCreatesAndDetectsFirstWriter(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
	// The actual update created its writer lock; retain that empty original
	// outside the module to model a pre-lock journal, without deleting evidence.
	path := filepath.Join(s.moduleDir("pm2-manager"), pm2ConfigurationJournalLock)
	if err := os.Rename(path, filepath.Join(t.TempDir(), "retained-original-lock")); err != nil {
		t.Fatal(err)
	}
	before := programQueueTree(t, s.Config.SecurityDir)
	read, err := s.readPM2ConfigurationJournalLease()
	if err != nil || !read.current() {
		t.Fatal(err)
	}
	defer read.Close()
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("read created or repaired a lock")
	}
	writer, err := s.lockPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if read.current() {
		t.Fatal("read-only absence remained authoritative after first writer")
	}
}
func TestPM2JournalReadLeaseSharesAndRefusesUnsettledWriter(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
	a, err := s.readPM2ConfigurationJournalLease()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.readPM2ConfigurationJournalLease()
	if err != nil {
		t.Fatal(err)
	}
	if w, err := s.lockPM2ConfigurationJournal(); err == nil {
		w.Close()
		t.Fatal("writer acquired shared journal")
	}
	a.Close()
	b.Close()
	w, err := s.lockPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	if r, err := s.readPM2ConfigurationJournalLease(); err == nil {
		r.Close()
		t.Fatal("reader attested unsettled writer")
	}
	w.Close()
}
func TestPM2JournalArchiveConfigurationGETReadsOldNonceWithoutHistoryOrReplay(t *testing.T) {
	s, _, in := pm2ArchiveReadCompleteFixture(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "pm2-manager", "version": "7.0.4-compat11"}); err != nil {
		t.Fatal(err)
	}
	// Obtain the cooperative journal lock once, as ordinary current writers do.
	w, err := s.lockPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	if response := pm2ConfigurationGET(s, "pm2_operation_id="+in.PM2OperationID); response.Code != 409 {
		t.Fatal("GET attested while original writer was unsettled", response.Code)
	}
	w.Close()
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("read invoked a service")
		return "", nil
	}
	for _, name := range []string{"history.json", "last-report.json"} {
		if err := os.WriteFile(filepath.Join(s.moduleDir("pm2-manager"), name), []byte("retain damaged retrospective evidence"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Even an unrelated unknown active record must not relabel this known old
	// original as absent. Unfiltered active reads still refuse the damage.
	if err := os.WriteFile(filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", "retained-unknown"), []byte("retain active original"), 0600); err != nil {
		t.Fatal(err)
	}
	before := programQueueTree(t, s.Config.SecurityDir)
	response := pm2ConfigurationGET(s, "resource_id="+in.ResourceID+"&pm2_operation_id="+in.PM2OperationID)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	var page map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || page["archived_original"] != true || page["selected_operation_absent"] == true {
		t.Fatal("GET hid consumed archived operation", err)
	}
	records := page["configuration_transactions"].([]any)
	if len(records) != 1 || records[0].(map[string]any)["pm2_operation_id"] != in.PM2OperationID {
		t.Fatal("wrong original selected")
	}
	if response := pm2ConfigurationGET(s, ""); response.Code != 409 {
		t.Fatal("unfiltered damaged active journal became valid")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("GET imported, repaired or wrote evidence")
	}
}
