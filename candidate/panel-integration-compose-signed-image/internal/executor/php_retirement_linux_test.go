//go:build linux

package executor

import (
	"local/panel/internal/core"
	"testing"
)

func TestRetiredPHPPrivilegedCreateRefused(t *testing.T) {
	for _, id := range []string{"php-legacy-52", "php-legacy-53-bookworm", "php-legacy-54-bookworm-compat3", "php-legacy-55-bookworm", "php-legacy-56-stretch", "php-legacy-70-stretch", "php-legacy-71-stretch", "php-legacy-72-buster", "php-legacy-73-buster", "php-legacy-74-bullseye-compat3"} {
		v := composeProjectRequest{JobID: core.ID(), ProjectID: core.ID(), Action: "create", Name: "retired-php", TemplateID: id, Compose: "services:\n  app:\n    image: retained\n"}
		if validateComposeRequest(v) == nil {
			t.Fatal("Root accepted retired create", id)
		}
	}
	for _, id := range []string{"php-legacy-80-bullseye-compat2", "php-legacy-81-bookworm-compat2"} {
		v := composeProjectRequest{JobID: core.ID(), ProjectID: core.ID(), Action: "create", Name: "active-php", TemplateID: id, Compose: "services:\n  app:\n    image: retained\n"}
		if err := validateComposeRequest(v); err != nil {
			t.Fatal("PHP8 rejected", id, err)
		}
	}
	for _, action := range []string{"start", "stop", "restart", "update"} {
		if err := validateComposeRequest(composeProjectRequest{JobID: core.ID(), ProjectID: core.ID(), Action: action}); err != nil {
			t.Fatal("existing lifecycle rejected", action, err)
		}
	}
}
