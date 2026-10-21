package geodata

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"
)

// Opt-in exact provider and ORIGINAL public authority, not a fixture/test key.
// Still an offline library test, NOT WAF activation or installed app acceptance.
func TestOfficialCountryPrefixesOctober2026(t *testing.T) {
	file := os.Getenv("YUNZHAN_COUNTRY_PREFIX_PROVIDER")
	if file == "" {
		t.Skip("official country provider authority not supplied; no real-data coverage claimed")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		OK       bool              `json:"ok"`
		Original bool              `json:"original_key_authority_verified"`
		Files    map[string]string `json:"files"`
	}
	if len(raw) > 32768 || json.Unmarshal(raw, &input) != nil || !input.OK || !input.Original {
		t.Fatal("provider input is not the original verified public authority")
	}
	pubRaw, err := os.ReadFile(input.Files["public_key"])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pubRaw)
	if hex.EncodeToString(sum[:]) != "659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75" {
		t.Fatal("not the original pinned application/data public key")
	}
	block, rest := pem.Decode(pubRaw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("noncanonical public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatal("wrong key type")
	}
	manifest, err := os.ReadFile(input.Files["manifest"])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(input.Files["signature"])
	if err != nil {
		t.Fatal(err)
	}
	authority, err := VerifyManifest(manifest, signature, pub, time.Now().UTC(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if authority.SHA256() != "072848fd40e0a17eaf4fb95ba7f7370e9dcde9b2841ac58412ac11512461e1e7" || authority.Manifest().SHA256 != "9e250f02722d1ad1780f88192f0e908af285478a33e76b88b349c9181ae9d0f5" {
		t.Fatal("not the exact original October2026 provider bytes")
	}
	compressed, err := os.Open(input.Files["compressed"])
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	started := time.Now()
	snapshot, err := Open(ctx, authority, compressed)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	opened := time.Since(started)
	exported, err := snapshot.CountryPrefixes(ctx, []string{"CN", "US"}, maxCountryNetworks)
	if err != nil {
		t.Fatal(err)
	}
	if exported.ManifestSHA256 != authority.SHA256() || exported.DatabaseSHA256 != authority.Manifest().SHA256 || exported.RecordsVisited < 1000000 || len(exported.Networks) < 1000 {
		t.Fatal("provider traversal or authority incomplete")
	}
	counts := map[string]int{}
	for i, row := range exported.Networks {
		if row.CountryCode != "CN" && row.CountryCode != "US" {
			t.Fatal("unselected country")
		}
		counts[row.CountryCode]++
		if i > 0 {
			previous := exported.Networks[i-1]
			if previous.Prefix.Overlaps(row.Prefix) || previous.Prefix.Addr().Compare(row.Prefix.Addr()) >= 0 {
				t.Fatal("provider networks overlap or are not canonical")
			}
		}
	}
	for _, text := range []string{"8.8.8.8", "1.1.1.1", "223.5.5.5", "2606:4700:4700::1111", "2001:4860:4860::8888", "192.168.1.1", "2001:db8::1", "::ffff:8.8.8.8"} {
		ip := netip.MustParseAddr(text).Unmap()
		location := snapshot.Lookup(text)
		matches := []string{}
		for _, row := range exported.Networks {
			if row.Prefix.Contains(ip) {
				matches = append(matches, row.CountryCode)
			}
		}
		wanted := location.Status == "located" && (location.CountryCode == "CN" || location.CountryCode == "US")
		if wanted && (len(matches) != 1 || matches[0] != location.CountryCode) || !wanted && len(matches) != 0 {
			t.Fatal("country export disagrees with independent direct lookup", text, location.Status, location.CountryCode, matches)
		}
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("original-key provider verified; raw_bytes=%d visits=%d exported=%d country_prefix_counts=%v full_validation=%s full_export=%s heap_live_bytes=%d allocated_bytes=%d", authority.Manifest().Bytes, exported.RecordsVisited, len(exported.Networks), counts, opened, time.Since(started)-opened, memory.HeapAlloc, memory.TotalAlloc)
}
