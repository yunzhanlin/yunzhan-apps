package core

import "testing"

func TestHardeningExecutorPayloadBindsOriginalQueueWithoutChangingOtherApps(t *testing.T) {
	settings := map[string]any{"profile": "baseline"}
	job := ID()
	got, err := softwareExecutorPayload("system-hardening", job, settings, "")
	if err != nil || got["job_id"] != job || len(got) != 3 {
		t.Fatal("original identity not bound", got, err)
	}
	for _, target := range []string{"system-hardening", "intrusion-prevention"} {
		got, err = softwareExecutorPayload(target, job, settings, "")
		if err != nil || got["job_id"] != job || len(got) != 3 {
			t.Fatal("original identity not bound", target, got, err)
		}
		for _, bad := range []string{"", "foreign", "01234567-89ab-4def-8abc-0123456789ab"} {
			if _, err = softwareExecutorPayload(target, bad, settings, ""); err == nil {
				t.Fatal("noncanonical original job accepted", target)
			}
		}
	}
	for _, id := range []string{"nginx-waf", "website-analytics", "files-sync", "apache-waf"} {
		got, err = softwareExecutorPayload(id, job, settings, "1.0")
		if err != nil || len(got) != 2 || got["version"] != "1.0" {
			t.Fatal("unrelated app request changed", id, got, err)
		}
		if _, exists := got["job_id"]; exists {
			t.Fatal("hardening protocol leaked into other apps", id)
		}
	}
}
