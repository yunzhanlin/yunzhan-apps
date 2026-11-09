package core

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func memcachedPlanFixture(t *testing.T) (string, []byte, MemcachedUpdatePlan) {
	t.Helper()
	target, err := dockerTemplate("memcached-cache", 21212)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(strings.Replace(target, appcatalog.MemcachedDigestImage, "memcached:1.6.45-alpine", 1))
	if !strings.Contains(target, "test: [\"CMD-SHELL\", "+strconv.Quote(MemcachedHealthCommand)+"]") {
		t.Fatal("runtime health command no longer matches the reviewed old YAML template")
	}
	// This actual old template digest was independently observed on the
	// existing ARM QA project; no live project IDs or configuration are used.
	if Hash(string(legacy)) != "297589552b027e123ab1c309c89fa9a53e37ca0446c509ca344171563e4abb6d" {
		t.Fatal("old reviewed template no longer matches the actual existing format")
	}
	p, err := MemcachedComposeUpdatePlan(strings.Repeat("a", 32), strings.Repeat("b", 64), legacy, 21212, strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64), strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	return target, legacy, p
}

func TestMemcachedUpdatePlanBindsActualOldTemplateAndPreservesItsBytes(t *testing.T) {
	target, legacy, p := memcachedPlanFixture(t)
	before := string(legacy)
	if p.Format != 1 || p.AppID != "memcached" || p.TargetImage != appcatalog.MemcachedDigestImage || p.HostPort != 21212 || p.AlreadyPinned || !p.CacheMayBeCleared || !registryDigestValid(p.ProjectSHA256) || p.ComposeSHA256 != Hash(before) {
		t.Fatal(p)
	}
	again, err := MemcachedComposeUpdatePlan(p.ProjectID, p.MetadataSHA256, legacy, p.HostPort, p.ContainerID, p.RuntimeImageID, p.RuntimeConfigSHA256)
	if err != nil || p != again || string(legacy) != before {
		t.Fatal("preview changed configuration or identity", again, err)
	}
	pinned, err := MemcachedComposeUpdatePlan(p.ProjectID, p.MetadataSHA256, []byte(target), p.HostPort, p.ContainerID, p.RuntimeImageID, p.RuntimeConfigSHA256)
	if err != nil || !pinned.AlreadyPinned || pinned.ProjectSHA256 == p.ProjectSHA256 || !pinned.CacheMayBeCleared {
		t.Fatal("a pinned reference cannot claim that current container recreation is harmless", pinned, err)
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "services:") || strings.Contains(string(raw), "healthy") || strings.Contains(string(raw), "verified") {
		t.Fatal("a preview must not expose raw YAML or masquerade as authority or fresh health proof")
	}
}

func TestMemcachedUpdatePlanRejectsManualChangesRatherThanNormalizingThemAway(t *testing.T) {
	_, legacy, p := memcachedPlanFixture(t)
	for name, raw := range map[string]string{
		"public-port":   strings.Replace(string(legacy), "127.0.0.1", "0.0.0.0", 1),
		"memory":        strings.Replace(string(legacy), "128", "256", 1),
		"other-version": strings.Replace(string(legacy), "1.6.45", "1.6.44", 1),
		"unknown-field": string(legacy) + "unknown: true\n",
		"comment":       "# edited\n" + string(legacy),
		"mount":         string(legacy) + "volumes:\n  data: {}\n",
		"CRLF":          strings.ReplaceAll(string(legacy), "\n", "\r\n"),
		"nul":           string(legacy) + "\x00",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := MemcachedComposeUpdatePlan(p.ProjectID, p.MetadataSHA256, []byte(raw), p.HostPort, p.ContainerID, p.RuntimeImageID, p.RuntimeConfigSHA256); err == nil {
				t.Fatal("changed configuration silently adopted")
			}
		})
	}
}

func TestMemcachedUpdatePlanIdentityCannotBeBorrowedByAnotherProjectOrContainer(t *testing.T) {
	_, legacy, p := memcachedPlanFixture(t)
	for _, scenario := range []string{"project", "metadata", "container", "image", "runtime-config"} {
		project, metadata, container, image, runtimeSHA := p.ProjectID, p.MetadataSHA256, p.ContainerID, p.RuntimeImageID, p.RuntimeConfigSHA256
		switch scenario {
		case "project":
			project = strings.Repeat("1", 32)
		case "metadata":
			metadata = strings.Repeat("2", 64)
		case "container":
			container = strings.Repeat("3", 64)
		case "image":
			image = "sha256:" + strings.Repeat("4", 64)
		case "runtime-config":
			runtimeSHA = strings.Repeat("5", 64)
		}
		changed, err := MemcachedComposeUpdatePlan(project, metadata, legacy, p.HostPort, container, image, runtimeSHA)
		if err != nil || changed.ProjectSHA256 == p.ProjectSHA256 {
			t.Fatal("original preview identity was reused", scenario, err)
		}
	}
	for _, id := range []string{"", "../escape", strings.Repeat("A", 32)} {
		if _, err := MemcachedComposeUpdatePlan(id, p.MetadataSHA256, legacy, p.HostPort, p.ContainerID, p.RuntimeImageID, p.RuntimeConfigSHA256); err == nil {
			t.Fatal("invalid project", id)
		}
	}
	for _, image := range []string{"memcached:latest", "sha256:" + strings.Repeat("D", 64), "sha256:short"} {
		if _, err := MemcachedComposeUpdatePlan(p.ProjectID, p.MetadataSHA256, legacy, p.HostPort, p.ContainerID, image, p.RuntimeConfigSHA256); err == nil {
			t.Fatal("invalid observed image", image)
		}
	}
}

func TestMemcachedRollbackPinsExactLocalImageWithoutAdoptingManualConfiguration(t *testing.T) {
	target, legacy, p := memcachedPlanFixture(t)
	rollback, err := MemcachedComposeRollback(p)
	want := strings.Replace(target, "image: "+appcatalog.MemcachedDigestImage+"\n", "image: "+p.RuntimeImageID+"\n", 1)
	if err != nil || string(rollback) != want || Hash(want) != p.RollbackComposeSHA256 || string(legacy) == want {
		t.Fatal("rollback used mutable original tag or changed non-image settings", err)
	}
	reopened, err := MemcachedComposeUpdatePlan(p.ProjectID, p.MetadataSHA256, rollback, p.HostPort, p.ContainerID, p.RuntimeImageID, p.RuntimeConfigSHA256)
	if err != nil || reopened.CurrentImage != p.RuntimeImageID || reopened.ComposeSHA256 != p.RollbackComposeSHA256 || ValidateMemcachedUpdatePlan(reopened, p.ProjectID) != nil {
		t.Fatal("original opaque rollback template cannot be inspected", err)
	}
	wrong := strings.Replace(want, p.RuntimeImageID, "sha256:"+strings.Repeat("f", 64), 1)
	if _, err := MemcachedComposeUpdatePlan(p.ProjectID, p.MetadataSHA256, []byte(wrong), p.HostPort, p.ContainerID, p.RuntimeImageID, p.RuntimeConfigSHA256); err == nil {
		t.Fatal("other pinned image silently adopted")
	}
	for _, scenario := range []string{"source-hash", "rollback-hash", "current-image"} {
		q := p
		switch scenario {
		case "source-hash":
			q.ComposeSHA256 = Hash("other")
		case "rollback-hash":
			q.RollbackComposeSHA256 = Hash("other")
		case "current-image":
			q.CurrentImage = "sha256:" + strings.Repeat("f", 64)
		}
		q.ProjectSHA256, _ = memcachedPlanIdentity(q)
		if ValidateMemcachedUpdatePlan(q, q.ProjectID) == nil {
			t.Fatal("self-sealed altered rollback binding accepted", scenario)
		}
	}
}
