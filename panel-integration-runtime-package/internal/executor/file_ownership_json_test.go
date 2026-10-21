package executor

import (
	"encoding/json"
	"testing"
)

func TestFileOwnerClosedJSONRequiresBothExplicitIdentifiers(t *testing.T) {
	for _, data := range []string{`{}`, `null`, `{"gid":0}`, `{"uid":null,"gid":0}`, `{"uid":0,"GID":0}`, `{"uid":0,"gid":0,"uid":1}`, `{"uid":0,"gid":0,"path":"/private"}`, `{"uid":0,"gid":4294967295}`, `{"uid":0,"gid":0} {}`} {
		var out fileOwner
		if json.Unmarshal([]byte(data), &out) == nil {
			t.Fatal("unsafe owner accepted", data)
		}
	}
	var out fileOwner
	if err := json.Unmarshal([]byte(`{"uid":0,"gid":1}`), &out); err != nil || out.UID != 0 || out.GID != 1 {
		t.Fatal(out, err)
	}
}
