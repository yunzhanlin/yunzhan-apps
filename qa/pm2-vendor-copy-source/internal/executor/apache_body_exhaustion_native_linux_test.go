//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// Called only after genuine native readiness, two independent site policies,
// and graceful activation. A separately confined runner owns the whole tmpfs.
// No fake errno, sparse byte fill, injected HTTP status or live panel is used.
func apacheBodyQuotaExhaustionHTTP(t *testing.T, ctx context.Context, root, mode string, request func(string, string, string, string) (*http.Response, error), hits *atomic.Int64) {
	t.Helper()
	if mode != "bytes" && mode != "inodes" {
		t.Fatal("closed private quota fixture mode required")
	}
	proof := map[string]any{"passed": false, "mode": mode, "native_engine": apacheBodyEngineVersion, "published_application_activation": false, "signed_application_receipt": false, "main_19100_started": false, "request_bytes_logged": false, "own_fill_expires_at_unit_closure": true}
	defer func() {
		if err := moduleWrite(filepath.Join(root, "exhaustion-proof.json"), proof); err != nil {
			t.Error("private native exhaustion proof", err)
		}
	}()
	var upload bytes.Buffer
	m := multipart.NewWriter(&upload)
	if err := m.SetBoundary("owned-quota-http-fixed-boundary"); err != nil {
		t.Fatal(err)
	}
	f, err := m.CreateFormFile("upload", "ordinary.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, strings.Repeat("a", 192<<10)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	payloads := []struct{ name, contentType, body string }{{"json", "application/json", `{"term":"` + strings.Repeat("a", 192<<10) + `"}`}, {"multipart", m.FormDataContentType(), upload.String()}}
	rows := []map[string]any{}
	check := func(phase, host string, payload struct{ name, contentType, body string }, wanted int) {
		t.Helper()
		before := hits.Load()
		r, err := request(host, "/quota", payload.body, payload.contentType)
		if err != nil {
			t.Fatal("actual full-cache request", phase, host, payload.name, err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(r.Body, 8193))
		r.Body.Close()
		digest := sha256.Sum256([]byte(payload.body))
		forwarded := hits.Load() == before+1
		unchanged := forwarded && r.Header.Get("X-Owned-Body-SHA") == hex.EncodeToString(digest[:])
		row := map[string]any{"phase": phase, "host": host, "format": payload.name, "payload_bytes": len(payload.body), "actual_status": r.StatusCode, "upstream_reached": forwarded, "original_body_verified_when_forwarded": unchanged}
		rows = append(rows, row)
		proof["actual_native_http"] = rows
		if readErr != nil || r.StatusCode != wanted || wanted == 200 && !unchanged || wanted == 503 && hits.Load() != before {
			t.Fatal("resource failure must not silently replay a truncated body", row, readErr)
		}
	}
	for _, host := range []string{"protected-a.localhost", "protected-b.localhost"} {
		for _, payload := range payloads {
			check("before-full", host, payload, 200)
		}
	}
	initial, err := verifyApacheBodyCacheQuota()
	if err != nil || initial.AvailableBytes != apacheBodyCacheBytes || initial.AvailableNodes != apacheBodyCacheInodes-3 {
		t.Fatal("two-site request cleanup/fresh physical budget", initial, err)
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	writer := exec.CommandContext(ctx, program, "-test.v", "-test.run=^TestApacheBodyCacheNativeUnprivilegedQuotaWriter$", "-test.timeout=40s")
	writer.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "PANEL_QA_APACHE_BODY_QUOTA_WRITER=" + mode, "PANEL_QA_APACHE_BODY_QUOTA_WRITER_SITE=" + apacheBodyConfigSiteA}
	writer.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 33, Gid: 33}}
	out, err := writer.CombinedOutput()
	if err != nil || len(out) > 64<<10 {
		t.Fatal("actual zero-capability quota writer", err, string(out))
	}
	var worker map[string]any
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "QUOTA-WORKER ") {
			if worker != nil || json.Unmarshal([]byte(strings.TrimPrefix(line, "QUOTA-WORKER ")), &worker) != nil {
				t.Fatal("ambiguous actual quota writer proof")
			}
		}
	}
	if worker == nil || worker["enospc"] != true || worker["uid"] != float64(33) || worker["cap_eff"] != "0000000000000000" {
		t.Fatal("actual ENOSPC/worker privilege proof missing", worker)
	}
	proof["actual_writer"] = worker
	full, err := verifyApacheBodyCacheQuota()
	if err != nil || mode == "bytes" && full.AvailableBytes != 0 || mode == "inodes" && full.AvailableNodes != 0 {
		t.Fatal("actual exhausted filesystem required", full, err)
	}
	proof["actual_full_budget"] = full
	snapshot := func() string {
		t.Helper()
		h := sha256.New()
		for _, id := range []string{apacheBodyConfigSiteA, apacheBodyConfigSiteB} {
			path := filepath.Join(apacheBodyTemporary, id)
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) > int(apacheBodyCacheInodes) {
				t.Fatal("bounded retained cache inventory", err)
			}
			for _, item := range entries {
				f, err := os.OpenFile(filepath.Join(path, item.Name()), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
				if err != nil {
					t.Fatal(err)
				}
				st, err := f.Stat()
				if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
					f.Close()
					t.Fatal("retained file identity/type/mode", err)
				}
				fmt.Fprintf(h, "%s/%s:%d:%o\n", id, item.Name(), st.Size(), st.Mode())
				_, err = io.Copy(h, f)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	before := snapshot()
	for _, host := range []string{"protected-a.localhost", "protected-b.localhost"} {
		for _, payload := range payloads {
			check("actual-full", host, payload, 503)
		}
		check("small-memory-only-at-full", host, struct{ name, contentType, body string }{"small-json", "application/json", `{"term":"ordinary"}`}, 200)
	}
	if after := snapshot(); after != before {
		t.Fatal("cache exhaustion changed retained files or leaked failed request files", before, after)
	}
	proof["retained_files_sha256"] = before
	proof["retained_fill_unchanged_no_failed_request_file_leak"] = true
	proof["passed"] = !t.Failed()
}
