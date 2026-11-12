//go:build linux

package executor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestFTPTransferHistoryRejectsOtherServicesAndKeepsRelativePaths(t *testing.T) {
	const site = "b563202a0e974f23bc2f36cc981d733e"
	const root = "/srv/panel/sites"
	const binary = "/opt/panel/app-modules/pure-ftpd/runtime/pure-ftpd"
	const upload = "(qa-user@127.0.0.1) [NOTICE] " + root + "/" + site + "/public//目录/report 01.txt uploaded  (123 bytes, 2.75KB/sec)"
	base := ftpTransferJournalEntry{Time: "1794441600000000", Unit: ftpTransferUnit, Executable: binary,
		Identifier: "pure-ftpd", Transport: "syslog", Message: transferMessage(t, upload)}
	record, ok := parseFTPTransfer(base, binary, root)
	if !ok || record.SiteID != site || record.Path != "/目录/report 01.txt" || record.Username != "qa-user" ||
		record.ClientIP != "127.0.0.1" || record.Direction != "upload" || record.Bytes != 123 || record.KiBPerSecond != 2.75 {
		t.Fatalf("unexpected transfer: %+v, %t", record, ok)
	}
	for name, change := range map[string]func(*ftpTransferJournalEntry){
		"foreign executable": func(row *ftpTransferJournalEntry) { row.Executable = "/usr/sbin/pure-ftpd" },
		"foreign unit":       func(row *ftpTransferJournalEntry) { row.Unit = "pure-ftpd.service" },
		"foreign transport":  func(row *ftpTransferJournalEntry) { row.Transport = "journal" },
		"unmanaged home": func(row *ftpTransferJournalEntry) {
			row.Message = transferMessage(t, strings.Replace(upload, root, "/outside", 1))
		},
		"parent path": func(row *ftpTransferJournalEntry) {
			row.Message = transferMessage(t, strings.Replace(upload, "/目录/", "/../", 1))
		},
		"unrelated notice": func(row *ftpTransferJournalEntry) {
			row.Message = transferMessage(t, strings.Replace(upload, "uploaded", "removed", 1))
		},
		"binary message": func(row *ftpTransferJournalEntry) { row.Message = json.RawMessage("[0,255]") },
	} {
		t.Run(name, func(t *testing.T) {
			entry := base
			change(&entry)
			if value, ok := parseFTPTransfer(entry, binary, root); ok {
				t.Fatalf("accepted unverified transfer: %+v", value)
			}
		})
	}
}

func TestFTPTransferHistoryFiltersBoundedJournalRecords(t *testing.T) {
	const site = "b563202a0e974f23bc2f36cc981d733e"
	const root = "/srv/panel/sites"
	const binary = "/opt/panel/app-modules/pure-ftpd/runtime/pure-ftpd"
	const download = "(qa-user@127.0.0.1) [NOTICE] " + root + "/" + site + "/public//test.txt downloaded  (123 bytes, 0.00KB/sec)"
	entry := ftpTransferJournalEntry{Time: "1794441600000000", Unit: ftpTransferUnit, Executable: binary,
		Identifier: "pure-ftpd", Transport: "syslog", Message: transferMessage(t, download)}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	journal := append(raw, '\n')
	repeated := append(append([]byte{}, journal...), journal...)
	at := time.UnixMicro(1794441600000000).UTC()
	query := core.FTPTransferQuery{Minutes: 15, Limit: 1, Direction: "download", Username: "qa-user", SiteID: site}
	report, err := ftpTransferRecords(repeated, binary, root, query, at.Add(-time.Minute), at)
	if err != nil || len(report.Events) != 1 || !report.HasMore {
		t.Fatalf("unexpected bounded result: %+v, %v", report, err)
	}
	query.Direction = "upload"
	report, err = ftpTransferRecords(repeated, binary, root, query, at.Add(-time.Minute), at)
	if err != nil || len(report.Events) != 0 || report.HasMore {
		t.Fatalf("unexpected filtered result: %+v, %v", report, err)
	}
}

func transferMessage(t *testing.T, value string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
