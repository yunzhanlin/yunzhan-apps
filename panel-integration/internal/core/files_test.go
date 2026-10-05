package core

import "testing"

func TestFilePathsRejectEscapeAndReservedMetadata(t *testing.T) {
	for _, p := range []string{"../x", "/etc/passwd", "a/../b", "a\\b", ".panel-files/trash", "a//b", "a/./b", "bad\x00name", "a\nname"} {
		if ValidFilePath(p, false) {
			t.Fatal("accepted unsafe path", p)
		}
	}
	for _, p := range []string{"index.php", "assets/中文.svg", ".env", "a b/file.txt"} {
		if !ValidFilePath(p, false) {
			t.Fatal("rejected valid relative path", p)
		}
	}
	if !ValidFilePath(".", true) || ValidFilePath(".", false) {
		t.Fatal("root-only navigation check")
	}
}
