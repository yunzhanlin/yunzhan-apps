package executor

import "testing"

func TestWAFVersionCapabilitiesRejectUnknownFutureAndAcceptRetentionPatch(t *testing.T) {
	for _, test := range []struct {
		version                 string
		rotation, retention, cc bool
	}{
		{"2.0.1", false, false, false}, {"2.3.0", false, false, true},
		{"2.4.0", true, false, true}, {"2.5.0", true, true, true}, {"2.5.1", true, true, true},
		{"2.5.2", false, false, false}, {"2.6.0", false, false, false}, {"3.0.0", false, false, false}, {"", false, false, false},
	} {
		if wafBodyRotationVersion(test.version) != test.rotation || wafRetentionVersion(test.version) != test.retention || wafCCObservationVersion(test.version) != test.cc {
			t.Fatal("incorrect version capability", test.version)
		}
	}
}
