package core

import (
	"strings"
	"testing"
)

func TestIsolatedLegacyPHPTemplates(t *testing.T) {
	if len(LegacyPHPImages) != 12 {
		t.Fatal("legacy matrix incomplete")
	}
	for id, image := range LegacyPHPImages {
		if !dockerImagePattern.MatchString(image) {
			t.Fatal("invalid digest", id, image)
		}
		source, e := dockerTemplate(id, 23000)
		if e != nil {
			t.Fatal(e)
		}
		for _, part := range []string{image, "read_only: true", "internal: true", "no-new-privileges:true", "127.0.0.1:23000:8080", "site-data:/var/www/html", "disable_functions=exec"} {
			if !strings.Contains(source, part) {
				t.Fatal(id, part)
			}
		}
		if strings.Contains(source, "/srv/panel/sites:") {
			t.Fatal("host site exposed")
		}
	}
}
func TestDualServiceTemplates(t *testing.T) {
	for _, id := range []string{"rabbitmq", "openlitespeed"} {
		source, e := dockerTemplate(id, 23000)
		if e != nil || strings.Count(source, `- "127.0.0.1:`) != 2 || !strings.Contains(source, "@sha256:") {
			t.Fatal(id, e)
		}
		if _, e = dockerTemplate(id, 65535); e == nil {
			t.Fatal("invalid dual port")
		}
	}
}
