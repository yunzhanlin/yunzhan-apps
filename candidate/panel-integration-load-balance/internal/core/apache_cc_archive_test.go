package core

import (
	"strings"
	"testing"
)

func TestApacheCCArchiveRequestBindsExactOriginalScalars(t *testing.T) {
	good := `{"request_id":"` + strings.Repeat("a", 32) + `","expected_revision":2,"allow_incomplete":false}`
	v, err := DecodeApacheCCArchiveRequest([]byte(good))
	if err != nil || v.RequestID != strings.Repeat("a", 32) || v.ExpectedRevision != 2 || v.AllowIncomplete {
		t.Fatal(v, err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"request_id"`, `"Request_ID"`, 1),
		strings.Replace(good, `"request_id"`, `"request_\u0069d"`, 1),
		strings.Replace(good, `"expected_revision":2`, `"expected_revision":2,"expected_revision":3`, 1),
		strings.Replace(good, `"expected_revision":2`, `"expected_revision":"2"`, 1),
		strings.Replace(good, `"expected_revision":2`, `"expected_revision":2.0`, 1),
		strings.Replace(good, `"expected_revision":2`, `"expected_revision":0`, 1),
		strings.Replace(good, `false`, `null`, 1), strings.Replace(good, `false`, `0`, 1),
		strings.Replace(good, `"allow_incomplete":false`, `"path":"/etc/shadow"`, 1),
		strings.Replace(good, `"request_id":"`+strings.Repeat("a", 32)+`"`, `"request_id":"../../private"`, 1),
		good + `{}`, `[]`, `{}`, strings.Repeat(" ", 1025) + good,
	} {
		if _, err := DecodeApacheCCArchiveRequest([]byte(bad)); err == nil {
			t.Fatal("unsafe archive request accepted", bad)
		}
	}
	for _, part := range []string{"0", "31", "127"} {
		if _, err := ApacheCCArchivePart(part); err != nil {
			t.Fatal(err)
		}
	}
	for _, part := range []string{"", "-1", "128", "01", "+1", "1.0", "1/../../private"} {
		if _, err := ApacheCCArchivePart(part); err == nil {
			t.Fatal("unbounded chunk identity accepted", part)
		}
	}
}

func TestApacheCCArchiveDigestConfirmationsAreClosedAndDistinct(t *testing.T) {
	for _, kind := range []string{"retain", "history"} {
		confirm := "confirm_unknown"
		decode := func(b []byte) error { _, err := DecodeApacheCCArchiveRetention(b); return err }
		if kind == "history" {
			confirm = "confirm_preserve"
			decode = func(b []byte) error { _, err := DecodeApacheCCArchiveHistory(b); return err }
		}
		good := `{"sha256":"` + strings.Repeat("a", 64) + `","` + confirm + `":true}`
		if err := decode([]byte(good)); err != nil {
			t.Fatal(kind, err)
		}
		for _, bad := range []string{strings.Replace(good, `true`, `false`, 1), strings.Replace(good, `true`, `null`, 1), strings.Replace(good, `true`, `1`, 1), strings.Replace(good, `"sha256"`, `"SHA256"`, 1), strings.Replace(good, `"sha256"`, `"sha\u003256"`, 1), strings.Replace(good, `"sha256"`, `"sha256":"`+strings.Repeat("b", 64)+`","sha256"`, 1), strings.Replace(good, `}`, `,"path":"/etc/shadow"}`, 1), good + `{}`, `{}`, `null`, strings.Repeat(" ", 1025) + good} {
			if decode([]byte(bad)) == nil {
				t.Fatal("unsafe digest confirmation", kind, bad)
			}
		}
	}
}
