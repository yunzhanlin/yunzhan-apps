//go:build linux

package executor

import (
	"strings"
	"testing"
)

func TestThreatIDSPrivateJSONRejectsAmbiguousNestedIdentity(t *testing.T) {
	type identity struct {
		Format int               `json:"format"`
		Files  map[string]string `json:"files"`
	}
	for _, input := range []string{
		`{"format":1,"format":1}`, `{"format":1,"FORMAT":1}`,
		`{"format":1,"for\u006dat":1}`, `{"format":1,"files":{"bin":"a","bin":"a"}}`,
		`{"format":1,"extra":1}`, `{"format":null}`, `null`, `[]`, `1`,
		`{"format":1} {}`, `{"format":1,"files":null}`,
		`{"format":1,"files":` + strings.Repeat("[", 17) + `1` + strings.Repeat("]", 17) + `}`,
		strings.Repeat(" ", 128<<10) + `{"format":1}`,
	} {
		var out identity
		if decodeThreatIDSPrivateJSON([]byte(input), &out) == nil {
			t.Fatal("ambiguous private identity accepted", input[:min(len(input), 160)])
		}
	}
	var out identity
	if err := decodeThreatIDSPrivateJSON([]byte(`{"format":1,"files":{"LICENSE":"sha","bin":"sha"}}`), &out); err != nil || out.Format != 1 || len(out.Files) != 2 {
		t.Fatal("canonical runtime map rejected", out, err)
	}
}
