package runtimecatalog

import (
	"reflect"
	"strings"
	"testing"
)

func TestPHPSecurity20261021ExactOfficialSourcesAndHistoricalIdentities(t *testing.T) {
	expected := map[string]string{
		"8.2.35": "9db4204f0a2d1911277ae832185e07bb4c3b3559772753a70d2968ca346d6910",
		"8.3.36": "c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53",
		"8.4.27": "5bafed9994c1a49796b25b5f61c22c9183bfe046b6acc7b363842d03c77f972f",
		"8.5.12": "81a0f450349e84b08eb43faa85f8a4c835684f3cc1c50471775d1317a046c525",
	}
	if len(PHPSecurity20261021) != 4 || len(PHP) != 4 || len(PHPReleases()) != 8 {
		t.Fatal("Security releases must not replace or relabel historical entries")
	}
	for _, item := range PHPSecurity20261021 {
		if item.ID != "php-"+item.Version || item.Family != "php" || item.SHA256 != expected[item.Version] || item.URL != "https://www.php.net/distributions/php-"+item.Version+".tar.gz" || !strings.HasPrefix(item.Version, item.Series+".") {
			t.Fatal("Incorrect official fixed source", item)
		}
		found, ok := Find(item.ID)
		if !ok || !reflect.DeepEqual(found, item) {
			t.Fatal("New reviewed source unavailable to fixed runtime handler", item)
		}
		if item.Prefix() != "/opt/panel/runtimes/php/"+item.Version || item.CLI() != item.Prefix()+"/bin/php" || item.FPM() != item.Prefix()+"/sbin/php-fpm" {
			t.Fatal("Security patch must have a separate exact installation prefix", item)
		}
	}
	for _, old := range PHP {
		found, ok := Find(old.ID)
		if !ok || !reflect.DeepEqual(found, old) {
			t.Fatal("Historical runtime/rollback identity changed", old)
		}
	}
}

func TestPHPSecurityReleaseListsCannotMutateFixedCatalogueSlices(t *testing.T) {
	first := PHPReleases()
	first[0].SHA256 = "untrusted"
	first[len(first)-1].Version = "untrusted"
	if PHPReleases()[0].SHA256 == "untrusted" || PHPReleases()[len(first)-1].Version == "untrusted" {
		t.Fatal("Caller changed the fixed source catalogue")
	}
	seen := map[string]bool{}
	for _, release := range All() {
		if seen[release.ID] {
			t.Fatal("Duplicate reviewed runtime ID", release.ID)
		}
		seen[release.ID] = true
	}
}
