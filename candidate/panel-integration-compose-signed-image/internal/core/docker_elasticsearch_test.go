package core

import (
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestElasticsearchSnapshotTemplateBindsFixedIndependentRepository(t *testing.T) {
	const port = 19201
	password := Token()
	source := elasticsearchCompose(ElasticsearchSnapshotTemplate, port, password)
	legacy := elasticsearchCompose(ElasticsearchLegacyTemplate, port, password)
	if strings.Contains(legacy, "path.repo:") || strings.Contains(legacy, "snapshots:") {
		t.Fatal("historical deployment unexpectedly enables snapshot storage")
	}
	for _, value := range []string{
		"image: " + dockerElasticsearchImage,
		"path.repo: " + ElasticsearchSnapshotRepositoryPath,
		"snapshots:/usr/share/elasticsearch/logs",
		"data:/usr/share/elasticsearch/data",
		"\"127.0.0.1:19201:9200\"",
		"mem_limit: 1g",
	} {
		if !strings.Contains(source, value) {
			t.Errorf("snapshot template missing %q", value)
		}
	}
	if !ElasticsearchSnapshotComposeMatches(source, port, password) {
		t.Fatal("the exact reviewed snapshot Compose recipe was refused")
	}
	for old, bad := range map[string]string{
		ElasticsearchSnapshotRepositoryPath:       "/",
		"snapshots:/usr/share/elasticsearch/logs": "data:/usr/share/elasticsearch/logs",
		"127.0.0.1:19201:9200":                    "0.0.0.0:19201:9200",
		dockerElasticsearchImage:                  "docker.elastic.co/elasticsearch/elasticsearch:9.1.4",
	} {
		if ElasticsearchSnapshotComposeMatches(strings.Replace(source, old, bad, 1), port, password) {
			t.Errorf("snapshot template accepted modified %q", old)
		}
	}
}

func TestRegistryElasticsearchSnapshotTemplateRequiresItsSignedVersion(t *testing.T) {
	manifest := appcatalog.Manifest{
		ID: "elasticsearch", Version: elasticsearchSnapshotAppVersion, Risk: "maintained",
		Delivery: appcatalog.Delivery{Provider: "compose", Target: ElasticsearchSnapshotTemplate, ManageRoute: "docker", Image: dockerElasticsearchImage},
	}
	if err := validateRegistryComposeDelivery(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Version = "9-compat1"
	if validateRegistryComposeDelivery(manifest) == nil {
		t.Fatal("old package may not claim the snapshot template")
	}
}

func TestElasticsearchSnapshotRequestsRequireExactNamesAndNewTarget(t *testing.T) {
	good := ElasticsearchSnapshotRequest{Index: "events-2026", Snapshot: "before-deploy", Password: "administrator-password"}
	if err := good.Validate(false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"*", "events,other", "events%2fother", ".security", "events/other", "events+1", "Alpha", ""} {
		altered := good
		altered.Index = name
		if altered.Validate(false) == nil {
			t.Errorf("unexpected source index %q", name)
		}
	}
	for _, name := range []string{"events-2026", "restored-*", "unrelated", ""} {
		altered := good
		altered.RestoreIndex = name
		if altered.Validate(true) == nil {
			t.Errorf("unexpected restore index %q", name)
		}
	}
	good.RestoreIndex = "restored-events-2026-" + strings.Repeat("a", 32)
	if good.Validate(true) != nil || good.Validate(false) == nil {
		t.Fatal("restore target was not bound to the selected action")
	}
	good.Password = "line\nbreak"
	if good.Validate(true) == nil {
		t.Fatal("credential escaped its configuration line")
	}
}
