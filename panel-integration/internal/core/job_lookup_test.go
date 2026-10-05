package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJobLookupBeyondRecentList(t *testing.T) {
	s := testStore(t)
	job, e := s.CreateSite("history", "history-test", "history", "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE jobs SET state='succeeded',payload='{"private":"not-for-api"}' WHERE id=?`, job); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 105; i++ {
		if _, e = s.DB.Exec(`INSERT INTO jobs(id,site_id,kind,state,created_at,updated_at) VALUES(?,?,'configure','succeeded','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')`, ID(), siteID); e != nil {
			t.Fatal(e)
		}
	}
	recent, e := s.Jobs()
	if e != nil || len(recent) != 100 {
		t.Fatal("recent limit", len(recent), e)
	}
	for _, j := range recent {
		if j.ID == job {
			t.Fatal("old job unexpectedly recent")
		}
	}
	found, e := s.Job(job)
	if e != nil || found.ID != job || found.State != "succeeded" {
		t.Fatal("historical lookup failed", e)
	}
	raw, e := json.Marshal(found)
	if e != nil || strings.Contains(string(raw), "not-for-api") {
		t.Fatal("job payload exposed", e)
	}
	if _, e = s.Job("../../other"); e == nil {
		t.Fatal("invalid job accepted")
	}
}
