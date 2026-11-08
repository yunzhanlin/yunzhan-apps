package core

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func legacyPHPRenderedNginx(t *testing.T, id string) string {
	t.Helper()
	// Route-byte verification is independent of this test host. This explicit
	// AMD64 renderer is NOT a production architecture override or ARM PHP proof.
	compose, err := dockerTemplateOnArchitecture(id, 23000, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	commands := regexp.MustCompile(`(?m)^    command: (\[.*\])$`).FindAllStringSubmatch(compose, -1)
	if len(commands) != 2 {
		t.Fatal("actual legacy Compose bootstrap shape changed")
	}
	var command []string
	if json.Unmarshal([]byte(commands[1][1]), &command) != nil || len(command) != 1 {
		t.Fatal("actual legacy Nginx command is not the single fixed bootstrap")
	}
	// Compose unescapes $$ once. The shell's single-quoted heredoc must keep
	// Nginx variables unchanged; never execute this bootstrap in a test shell.
	bootstrap := strings.ReplaceAll(command[0], "$$", "$")
	_, source, found := strings.Cut(bootstrap, "CLOUDSTACK_CONFIG'\n")
	config, _, ended := strings.Cut(source, "\nCLOUDSTACK_CONFIG\n")
	if !found || !ended || !strings.HasPrefix(config, "pid /tmp/nginx.pid;\n") || !strings.HasSuffix(config, "\n}") {
		t.Fatal("actual rendered fixed Nginx heredoc cannot be verified")
	}
	return config + "\n"
}

func TestIsolatedLegacyPHPHiddenPathsAlwaysPrecedePHPRouting(t *testing.T) {
	for id := range LegacyPHPImages {
		config := legacyPHPRenderedNginx(t, id)
		deny, php := strings.Index(config, `  location ~ /\. { deny all; }`), strings.Index(config, `  location ~ \.php$ {`)
		if deny < 0 || php <= deny || strings.Count(config, `  location ~ /\.`) != 1 || !strings.Contains(config, "location = /.__cloudstack_health {") {
			t.Fatal("hidden PHP paths can reach the interpreter or fixed health changed", id)
		}
		old := strings.Replace(config, "  location ~ /\\. { deny all; }\n", "", 1)
		old = strings.Replace(old, "\n }\n}\n", "\n  location ~ /\\. { deny all; }\n }\n}\n", 1)
		if Hash(old) != "541d3277fdd8b61431fa02a21f2421a0e5cd2ed68d8e796873f9aeead4758e8c" {
			t.Fatal("fix changed more than original regex location order", id)
		}
	}
}
