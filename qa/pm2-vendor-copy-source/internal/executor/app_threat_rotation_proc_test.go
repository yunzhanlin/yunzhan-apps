package executor

import "testing"

func TestThreatIDSRotationProcAccountUsesKernelUIDsNotDirectoryOwnership(t *testing.T) {
	for _, text := range []string{"Uid:\t800\t800\t800\t800\n", "Name:\tnondumpable\nUid:\t0\t800\t0\t0\n", "Uid:\t800\t0\t0\t0\n", "Uid:\t0\t0\t800\t0\n", "Uid:\t0\t0\t0\t800\n"} {
		if matching, err := threatIDSProcAccount([]byte(text), 800); err != nil || !matching {
			t.Fatal("account descriptor hidden", text, matching, err)
		}
	}
	if matching, err := threatIDSProcAccount([]byte("Uid:\t0\t0\t0\t0\n"), 800); err != nil || matching {
		t.Fatal(matching, err)
	}
	for _, text := range []string{"", "Uid:\n", "Uid:\t800\t800\t800\n", "Uid:\t0800\t800\t800\t800\n", "Uid:\t-1\t800\t800\t800\n", "Uid:\t4294967296\t800\t800\t800\n", "Uid:\t800\t800\t800\t800\nUid:\n"} {
		if _, err := threatIDSProcAccount([]byte(text), 800); err == nil {
			t.Fatal("unknown UID metadata accepted", text)
		}
	}
}
