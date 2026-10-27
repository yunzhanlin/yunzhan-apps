package core

import (
	"testing"

	"local/panel/internal/appcatalog"
)

func TestStreamInstallVersionIsExactAndCandidateCompiledOnly(t *testing.T) {
	for _, check := range []func(string, string) error{ValidateSoftwareUpdate, ValidateSoftwareInstallVersion} {
		if err := check("load-balance", "1.8.5"); err != nil {
			t.Fatal("legacy supported HTTP delivery changed", err)
		}
		if err := check("load-balance", "1.9.0"); (err == nil) != appcatalog.LoadBalanceStreamAvailable() {
			t.Fatal("candidate version escaped the compiled channel gate", err)
		}
		for _, version := range []string{"1.9.0-compat1", "1.9.1", "2.0.0", "bad", ""} {
			if err := check("load-balance", version); err == nil {
				t.Fatal("unqualified version or alias accepted", version)
			}
		}
	}
}
