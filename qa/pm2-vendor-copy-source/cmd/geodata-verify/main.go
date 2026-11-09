// geodata-verify is a release/acceptance tool, not a panel installation API.
// It accepts explicit local inputs but only the existing pinned app key.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/geodata"
)

func boundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("invalid input file or size")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("input read failed or exceeds limit")
	}
	return data, nil
}
func verify() error {
	manifest := flag.String("manifest", "", "signed manifest file")
	signature := flag.String("signature", "", "detached base64 Ed25519 signature file")
	database := flag.String("database", "", "compressed database file")
	budget := flag.Duration("timeout", 90*time.Second, "acceptance-only validation deadline, maximum 5m; does not set panel runtime limits")
	flag.Parse()
	if *manifest == "" || *signature == "" || *database == "" || flag.NArg() != 0 || *budget <= 0 || *budget > 5*time.Minute {
		return fmt.Errorf("manifest, signature and database are required")
	}
	raw, err := boundedFile(*manifest, 4096)
	if err != nil {
		return err
	}
	sig, err := boundedFile(*signature, 128)
	if err != nil {
		return err
	}
	authority, err := geodata.VerifyManifest(raw, sig, appcatalog.Default().PublicKey, time.Now(), nil)
	if err != nil {
		return err
	}
	f, err := os.Open(*database)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != authority.Manifest().CompressedBytes {
		return fmt.Errorf("database input type or size differs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *budget)
	defer cancel()
	start := time.Now()
	snapshot, err := geodata.Open(ctx, authority, f)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	probes := map[string]geodata.Location{}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "223.5.5.5", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		got := snapshot.Lookup(ip)
		if got.Status != "located" || got.CountryCode == "" {
			return fmt.Errorf("public IP lookup failed for %s: %s", ip, got.Status)
		}
		probes[ip] = got
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"validation_only": true, "signed_by_pinned_app_key": true, "metadata": snapshot.Metadata(time.Now()), "elapsed_seconds": time.Since(start).Seconds(), "public_ip_probes": probes, "precision": "approximate IP network location, not a device or person's physical position"})
}
func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
