package executor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApacheBodyEvidenceJSONUnambiguousBoundedFixedSchema(t *testing.T) {
	want := apacheBodyFixtureRecord()
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got apacheBodyBuildRecord
	if err := apacheBodyDecodeJSON(b, &got); err != nil || apacheBodyRecordContract(got) != nil {
		t.Fatal("complete ready schema", err)
	}
	for _, data := range []string{
		`{"format":1,"format":1}`, `{"Format":1}`, `{"FORMAT":1}`,
		`{"source_sha256":{"source":"a","source":"b"}}`,
		`{"steps":[{"time":"a","time":"b"}]}`, `{"extra":1}`,
		`null`, `[]`, `{}`, `{} {}`, `{"format":1} trailing`,
		`{"steps":` + strings.Repeat("[", 7) + `0` + strings.Repeat("]", 7) + `}`,
		`{"completed_build_steps":[` + strings.Repeat(`"a",`, 4097) + `"b"]}`,
		`{"error":"` + strings.Repeat("a", 64<<10) + `"}`,
	} {
		if data == "{}" { // Parsing is not authority; the closed record contract rejects it.
			var empty apacheBodyBuildRecord
			if apacheBodyDecodeJSON([]byte(data), &empty) != nil || apacheBodyRecordContract(empty) == nil {
				t.Fatal("empty record promoted")
			}
			continue
		}
		if apacheBodyDecodeJSON([]byte(data), &got) == nil {
			t.Fatal("ambiguous or unbounded evidence accepted", data[:min(len(data), 120)])
		}
	}
}
