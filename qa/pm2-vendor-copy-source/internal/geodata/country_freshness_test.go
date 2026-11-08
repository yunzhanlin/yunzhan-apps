package geodata

import (
	"testing"
	"time"
)

func TestCountryDataFreshnessCannotGrantAuthorityAndDoesNotInvalidateHistoricalSignature(t *testing.T) {
	m, pub, key, _ := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, key)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	built := time.Unix(int64(m.BuildEpoch), 0)
	if a.StaleForNewPolicy(built) || a.StaleForNewPolicy(built.Add(90*24*time.Hour)) ||
		!a.StaleForNewPolicy(built.Add(90*24*time.Hour+time.Nanosecond)) ||
		!a.StaleForNewPolicy(built.Add(-time.Nanosecond)) ||
		!a.StaleForNewPolicy(time.Time{}) || (CountryAuthority{}).StaleForNewPolicy(fixtureNow) != true {
		t.Fatal("freshness or missing authority boundary lost")
	}
	if _, err := VerifyCountryManifest(raw, sig, pub, built.Add(91*24*time.Hour), nil); err != nil {
		t.Fatal("historical signature became unverifiable", err)
	}
}
