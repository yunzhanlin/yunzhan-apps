package core

import "testing"

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
			if err := mongoDBKernelCompatibility(tc.release); (err == nil) != tc.supported {
				t.Errorf("kernel %q: got %v, want supported=%v", tc.release, err, tc.supported)
			}
		})
	}
}
