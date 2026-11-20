package executor

import (
	"strings"
	"testing"

	"local/panel/internal/runtimecatalog"
)

func TestApacheCommittedSourceKeepsLegacySelectionAfterCatalogueUpdate(t *testing.T) {
	for _, id := range []string{runtimecatalog.ApacheLegacyID, runtimecatalog.ApacheCurrentID} {
		r, _ := runtimecatalog.Find(id)
		for _, root := range []string{r.Prefix(), `"` + r.Prefix() + `"`} {
			source := "# managed by panel\nServerRoot " + root + "\n# unrelated bytes retained\n"
			got, err := apacheSourceRelease(source)
			if err != nil || got != r {
				t.Fatalf("%s: %v / %v", id, got, err)
			}
		}
	}
}

func TestApacheCommittedSourceRejectsAmbiguityAndExternalRoots(t *testing.T) {
	root := "/opt/panel/runtimes/apache/2.4.68"
	valid := "# managed by panel\nServerRoot " + root + "\n"
	for name, source := range map[string]string{
		"missing":        "# managed by panel\n# ServerRoot " + root + "\n",
		"foreign":        strings.Replace(valid, root, "/usr", 1),
		"unreviewed":     strings.Replace(valid, "2.4.68", "2.4.70", 1),
		"variable":       strings.Replace(valid, root, "${HTTPD_ROOT}", 1),
		"include-only":   "# managed by panel\nInclude /etc/foreign.conf\n",
		"duplicate":      valid + "serverroot " + root + "\n",
		"cross-version":  valid + "ServerRoot /opt/panel/runtimes/apache/2.4.71\n",
		"extra-argument": strings.Replace(valid, root, root+" /foreign", 1),
		"nul":            valid + "\x00",
		"unmanaged":      strings.Replace(valid, "managed by panel", "unmanaged", 1),
		"oversize":       valid + strings.Repeat("#", 2<<20),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := apacheSourceRelease(source); err == nil {
				t.Fatal("ambiguous/unreviewed executable selection accepted")
			}
		})
	}
}

func TestApacheBodyLoaderUsesSameReviewedRuntimeAsConfiguration(t *testing.T) {
	base, previous, next := apacheBodyConfigFixture()
	base = strings.ReplaceAll(base, "/apache/2.4.68/", "/apache/2.4.71/")
	base = strings.ReplaceAll(base, "/apache/2.4.68\"", "/apache/2.4.71\"")
	enabled, err := transitionApacheBodySource(base, previous, next)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(enabled, "LoadModule unique_id_module /opt/panel/runtimes/apache/2.4.71/modules/mod_unique_id.so\n") || strings.Contains(enabled, "/apache/2.4.68") {
		t.Fatal("new configuration mixed old runtime module")
	}
	restored, err := transitionApacheBodySource(enabled, next, previous)
	if err != nil || restored != base {
		t.Fatal("deactivation changed unrelated config", err)
	}
	foreign := strings.Replace(base, "# managed by panel\n", "# managed by panel\nLoadModule unique_id_module /opt/panel/runtimes/apache/2.4.68/modules/mod_unique_id.so\n", 1)
	if _, err := transitionApacheBodySource(foreign, previous, next); err == nil {
		t.Fatal("cross-version unique_id module accepted")
	}
}
