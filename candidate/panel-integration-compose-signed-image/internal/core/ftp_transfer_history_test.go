package core

import (
	"net/url"
	"testing"
	"time"
)

func TestFTPTransferHistoryQueryChecksDatesAndFilterIdentity(t *testing.T) {
	values, err := url.ParseQuery("minutes=1440&end=2026-11-12T07%3A10%3A00%2B08%3A00&limit=250&direction=download&username=site-ftp&site_id=11111111111111112222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	query, err := ParseFTPTransferQuery(values)
	if err != nil || query.Minutes != 1440 || query.End != time.Date(2026, 11, 11, 23, 10, 0, 0, time.UTC) ||
		query.Limit != 250 || query.Direction != "download" || query.Username != "site-ftp" ||
		query.SiteID != "11111111111111112222222222222222" {
		t.Fatalf("valid query rejected: %+v, %v", query, err)
	}
	for _, raw := range []string{"minutes=15&minutes=60", "minutes=1", "end=relative", "limit=251",
		"direction=all", "username=1ftp", "site_id=not-owned-id", "_EXE=%2Fother", "unit=ftp"} {
		values, err := url.ParseQuery(raw)
		if err != nil {
			t.Fatal(err)
		}
		if query, err := ParseFTPTransferQuery(values); err == nil {
			t.Fatalf("invalid query admitted: %s, %+v", raw, query)
		}
	}
}
