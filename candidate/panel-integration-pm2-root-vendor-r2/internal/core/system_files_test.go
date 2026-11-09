package core

import "testing"

func TestValidSystemDirectory(t *testing.T) {
	for _, value := range []string{"/", "/srv/panel/sites", "/目录"} {
		if !ValidSystemDirectory(value) {
			t.Fatalf("rejected %q", value)
		}
	}
	for _, value := range []string{"", "etc", "//etc", "/etc/../root", "/etc/./a", "/etc/", "/etc\\passwd", "/etc/\n"} {
		if ValidSystemDirectory(value) {
			t.Fatalf("accepted %q", value)
		}
	}
}
