//go:build linux

package executor

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSummarizeSiteTrafficUsesOnlyManagedSiteLogs(t *testing.T) {
	base := t.TempDir()
	now := time.Now().In(trafficZone).Truncate(time.Second)
	id := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	today := now.Format(time.RFC3339)
	yesterday := now.AddDate(0, 0, -1).Format(time.RFC3339)
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(base, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("panel-"+id+".access.log", `{"time":"`+today+`","bytes":120}`+"\n"+`{"time":"`+today+`","bytes":30}`+"\n")
	write("panel-other.access.log", `{"time":"`+today+`","bytes":9000}`+"\n")
	archive, err := os.Create(filepath.Join(base, "panel-"+id+".access.log.20260922-100000.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(archive)
	if _, err := gz.Write([]byte(`{"time":"` + yesterday + `","bytes":75}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := summarizeSiteTraffic(base, []string{id}, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Partial || len(result.Days) != 7 || len(result.Sites) != 1 || result.Sites[0].TodayBytes != 150 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Days[5].Bytes != 75 || result.Days[6].Bytes != 150 || result.Days[6].Requests != 2 {
		t.Fatalf("unexpected days: %+v", result.Days)
	}
	if _, err = summarizeSiteTraffic(base, []string{"../etc/passwd"}, now); err == nil {
		t.Fatal("invalid site ID accepted")
	}
}

func TestSummarizeSiteTrafficRejectsSymlinkLog(t *testing.T) {
	base := t.TempDir()
	id := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	target := filepath.Join(base, "safe.txt")
	if err := os.WriteFile(target, []byte(strings.Repeat("x", 12)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "panel-"+id+".access.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := summarizeSiteTraffic(base, []string{id}, time.Now()); err == nil {
		t.Fatal("symlink log accepted")
	}
}
