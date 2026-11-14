package core

import (
	"strings"
	"testing"
)

func TestMongoDBKernelCompatibility(t *testing.T) {
	cases := []struct {
		release   string
		supported bool
	}{
		{"6.1.0-43-amd64", true},
		{"6.12.57+deb13-arm64", true},
		{"6.18.16-aws", true},
		{"6.19.0-1019-azure", false},
		{"6.20.0", false},
		{"7.0.0-38-generic", false},
		{"7.0.13", false},
		{"7.0.14", true},
		{"7.1.0-4-arm64", true},
		{"6.19", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.release, func(t *testing.T) {
			if err := mongoDBKernelCompatibilityOn(MongoDBLegacyTemplate, tc.release, ""); (err == nil) != tc.supported {
				t.Errorf("kernel %q: got %v, want supported=%v", tc.release, err, tc.supported)
			}
		})
	}
}

func TestMongoDB8038ChecksUbuntuUpstreamKernelWithoutWeakeningLegacy(t *testing.T) {
	cases := []struct {
		name, release, signature string
		legacy, patched          bool
	}{
		{"Ubuntu named old but patched", "7.0.0-38-generic", "Ubuntu 7.0.0-38.38-generic 7.0.14\n", false, true},
		{"Ubuntu unpatched", "7.0.0-37-generic", "Ubuntu 7.0.0-37.37-generic 7.0.13\n", false, false},
		{"missing signature", "7.0.0-38-generic", "", false, false},
		{"untrusted signature format", "7.0.0-38-generic", "Debian 7.0.0-38-generic 7.0.14", false, false},
		{"unexpected upstream series", "7.0.0-38-generic", "Ubuntu 7.0.0-38.38-generic 7.1.0", false, false},
		{"malformed upstream version", "7.0.0-38-generic", "Ubuntu 7.0.0-38.38-generic 7.0.bad", false, false},
		{"Linux before impacted range", "6.12.57+deb13-arm64", "", true, true},
		{"Linux patched version in release", "7.0.14", "", true, true},
		{"Linux later series", "7.1.2", "", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mongoDBKernelCompatibilityOn(MongoDBLegacyTemplate, tc.release, tc.signature) == nil; got != tc.legacy {
				t.Errorf("legacy compatibility = %v, want %v", got, tc.legacy)
			}
			if got := mongoDBKernelCompatibilityOn(MongoDB8038Template, tc.release, tc.signature) == nil; got != tc.patched {
				t.Errorf("8.0.38 compatibility = %v, want %v", got, tc.patched)
			}
		})
	}
}

func TestMongoDB8038RequiresExactFixedComposeAndLoopbackPort(t *testing.T) {
	const port = 27018
	password := Token()
	source := mongoDBCompose(MongoDB8038Template, port, password)
	if !MongoDB8038ComposeMatches(source, port, password) ||
		!strings.Contains(source, "127.0.0.1:27018:27017") ||
		!strings.Contains(source, "image: "+dockerMongoDB8038Image) ||
		strings.Count(source, password) != 1 {
		t.Fatal("patched Compose template has unexpected image, binding or credential propagation")
	}
	for _, image := range []string{dockerMongoDBImage, "mongo:8.0.38-noble"} {
		changed := strings.Replace(source, dockerMongoDB8038Image, image, 1)
		if MongoDB8038ComposeMatches(changed, port, password) {
			t.Errorf("patched Compose template accepted %s", image)
		}
	}
	if MongoDB8038ComposeMatches(source, port+1, password) ||
		MongoDB8038ComposeMatches(source, port, "abc") ||
		MongoDB8038ComposeMatches(source, port, Token()) {
		t.Fatal("patched Compose template accepted changed identity")
	}
}
