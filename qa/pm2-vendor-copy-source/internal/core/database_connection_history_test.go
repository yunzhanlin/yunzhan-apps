package core

import (
	"testing"
	"time"
)

func TestDatabaseConnectionHistoryKeepsFailureGapsAndExpires(t *testing.T) {
	store := testStore(t)
	base := time.Unix(1700000000, 0).UTC().Truncate(time.Minute)
	mysql, redis := 8, 3
	if err := store.RecordDatabaseConnectionSample(base, &mysql, &redis); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordDatabaseConnectionSample(base.Add(time.Minute), nil, &redis); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordDatabaseConnectionSample(base.Add(2*time.Minute), nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordDatabaseConnectionSample(base.Add(2*time.Minute+20*time.Second), &mysql, nil); err != nil {
		t.Fatal(err)
	}
	points, err := store.DatabaseConnectionHistory(base.Add(3 * time.Minute))
	if err != nil || len(points) != 3 {
		t.Fatalf("history: %v %#v", err, points)
	}
	if points[0].MySQL == nil || *points[0].MySQL != 8 || points[0].Redis == nil || *points[0].Redis != 3 {
		t.Fatalf("first sample corrupted: %#v", points[0])
	}
	if points[1].MySQL != nil || points[1].Redis == nil || *points[1].Redis != 3 {
		t.Fatalf("source failure became zero: %#v", points[1])
	}
	if points[2].MySQL == nil || *points[2].MySQL != 8 || points[2].Redis != nil {
		t.Fatalf("same-minute replacement failed: %#v", points[2])
	}
	bad := -1
	if err := store.RecordDatabaseConnectionSample(base.Add(3*time.Minute), &bad, nil); err == nil {
		t.Fatal("negative connection count accepted")
	}
	if err := store.RecordDatabaseConnectionSample(base.Add(25*time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	points, err = store.DatabaseConnectionHistory(base.Add(25 * time.Hour))
	if err != nil || len(points) != 1 || points[0].SampledAt != base.Add(25*time.Hour).Unix() {
		t.Fatalf("24-hour retention failed: %v %#v", err, points)
	}
}
