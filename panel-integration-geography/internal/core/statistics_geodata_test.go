package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func statisticsGeoSelectionFixture() StatisticsGeoSelection {
	return StatisticsGeoSelection{Action: "install", AppVersion: StatisticsGeoVersion, AppManifestSHA: strings.Repeat("a", 64), InstallationID: strings.Repeat("b", 32), Release: "2026-10", DataManifestSHA: strings.Repeat("c", 64)}
}
func TestStatisticsGeoClosedSelectionInstanceAndQueryBindings(t *testing.T) {
	in := statisticsGeoSelectionFixture()
	raw, _ := json.Marshal(in)
	decoded, err := DecodeStatisticsGeoSelection(raw)
	if err != nil || decoded != in {
		t.Fatal(decoded, err)
	}
	if v, err := ParseStatisticsGeoSelectionQuery(StatisticsGeoSelectionQuery(in)); err != nil || v != in {
		t.Fatal(v, err)
	}
	for _, v := range []string{strings.Replace(string(raw), `"action":"install"`, `"action":null`, 1), strings.Replace(string(raw), `"action":"install"`, `"Action":"install"`, 1), `{"action":"rollback",` + string(raw[1:]), string(raw) + ` {}`, strings.Replace(string(raw), `"installation_id":"`+in.InstallationID+`",`, "", 1)} {
		if _, err := DecodeStatisticsGeoSelection([]byte(v)); err == nil {
			t.Fatal("unbound/ambiguous selection accepted", v)
		}
	}
	for _, modify := range []func(*StatisticsGeoSelection){func(s *StatisticsGeoSelection) { s.AppVersion = "2.5.0" }, func(s *StatisticsGeoSelection) { s.AppVersion = "2.6.0-compat" }, func(s *StatisticsGeoSelection) { s.InstallationID = "" }, func(s *StatisticsGeoSelection) { s.Action = "shell" }, func(s *StatisticsGeoSelection) { s.DataManifestSHA = strings.Repeat("x", 64) }, func(s *StatisticsGeoSelection) { s.Release = "2026-13" }} {
		v := in
		modify(&v)
		if ValidateStatisticsGeoSelection(v) == nil {
			t.Fatal("unsupported job accepted")
		}
	}
	q := StatisticsGeoSelectionQuery(in)
	q.Add("url", "http://127.0.0.1/")
	if _, err := ParseStatisticsGeoSelectionQuery(q); err == nil {
		t.Fatal("caller URL accepted")
	}
}
func TestStatisticsGeoQueueStableActorAndImmutableFailedEvidence(t *testing.T) {
	s := testStore(t)
	in := statisticsGeoSelectionFixture()
	actor := strings.Repeat("d", 32)
	id, err := s.QueueStatisticsGeo(in, "geo-submit", actor)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.QueueStatisticsGeo(in, "geo-submit", actor)
	if err != nil || again != id {
		t.Fatal("lost reply replay changed job", again, err)
	}
	if _, err = s.QueueStatisticsGeo(in, "geo-submit", strings.Repeat("e", 32)); err == nil {
		t.Fatal("cross-actor replay accepted")
	}
	changed := in
	changed.InstallationID = strings.Repeat("f", 32)
	if _, err = s.QueueStatisticsGeo(changed, "geo-submit", actor); err == nil {
		t.Fatal("reinstall instance reused old key")
	}
	if _, err = s.QueueStatisticsGeo(in, "different-submit", actor); err == nil {
		t.Fatal("same app concurrent job accepted")
	}
	job, err := s.nextRuntimeInstallJob()
	if err != nil || job.ID != id || job.Kind != "statistics_geodata" {
		t.Fatal("data job not isolated in install lane", job, err)
	}
	if err = s.finishRuntime(job, "controlled failure", nil, false); err != nil {
		t.Fatal(err)
	}
	if err = s.RetryRuntime(id, actor); err == nil {
		t.Fatal("original failure reset for replay")
	}
	again, err = s.QueueStatisticsGeo(in, "geo-submit", actor)
	if err != nil || again != id {
		t.Fatal("failed original request replaced", again, err)
	}
	var count int
	var state string
	s.DB.QueryRow("SELECT count(*) FROM runtime_jobs WHERE kind='statistics_geodata'").Scan(&count)
	s.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", id).Scan(&state)
	if count != 1 || state != "failed" {
		t.Fatal(count, state)
	}
}
