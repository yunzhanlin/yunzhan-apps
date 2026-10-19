//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

// The outer runner supplies a genuinely bounded fresh tmpfs to one confined
// root:panel unit. No fake statfs, sparse file or command result proves quota.
// Created fill files deliberately remain until this owned mount is closed.
func TestApacheBodyCacheNativeHardLimitsPreserveAtExhaustion(t *testing.T) {
	mode := os.Getenv("PANEL_QA_APACHE_BODY_CACHE_QUOTA")
	if mode == "" {
		t.Skip("explicit private real tmpfs quota fixture required")
	}
	if os.Geteuid() != 0 || os.Getegid() == 0 || (mode != "bytes" && mode != "inodes") {
		t.Fatal("restricted root with panel primary group and fixed quota mode required")
	}
	initial, err := verifyApacheBodyCacheQuota()
	if err != nil || initial.AvailableBytes != apacheBodyCacheBytes || initial.AvailableNodes != apacheBodyCacheInodes-1 {
		t.Fatal("fresh actual dedicated hard quota required", initial, err)
	}
	const siteID = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	policy := core.DefaultWAFBodyPolicy()
	policy.Mode = "block"
	cfg := core.DefaultApacheWAFConfig()
	cfg.Body = &core.WAFBodyConfig{EngineJobID: "c8c1b6b9e4884ad49bc15fd7bf9d1f39", Sites: []core.WAFBodySitePolicy{{SiteID: siteID, Policy: policy}}}
	s := New(Config{SystemRoot: "/", SitesDir: "/srv/panel/sites"})
	if err := s.prepareApacheBodyStorage(context.Background(), cfg); err != nil {
		t.Fatal("prepare on true bounded cache", err)
	}
	dir := filepath.Join(apacheBodyTemporary, siteID)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("fresh test-owned site leaf required")
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(program, "-test.v", "-test.run=^TestApacheBodyCacheNativeUnprivilegedQuotaWriter$", "-test.timeout=40s")
	worker.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "PANEL_QA_APACHE_BODY_QUOTA_WRITER=" + mode}
	worker.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 33, Gid: 33}}
	output, err := worker.CombinedOutput()
	if err != nil || len(output) > 64<<10 {
		t.Fatal("actual capability-free www-data quota writer", err, string(output))
	}
	var result struct {
		Written int64  `json:"written"`
		Created int    `json:"created"`
		ENOSPC  bool   `json:"enospc"`
		UID     int    `json:"uid"`
		Caps    string `json:"cap_eff"`
	}
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "QUOTA-WORKER ") {
			if found || json.Unmarshal([]byte(strings.TrimPrefix(line, "QUOTA-WORKER ")), &result) != nil {
				t.Fatal("worker result malformed")
			}
			found = true
		}
	}
	created, written := result.Created, result.Written
	if !found || !result.ENOSPC || result.UID != 33 || result.Caps != "0000000000000000" || (mode == "bytes" && written != int64(apacheBodyCacheBytes)) || (mode == "inodes" && created != int(apacheBodyCacheInodes)-2) {
		t.Fatal("kernel quota was not actually enforced for the unprivileged writer", result)
	}
	full, err := verifyApacheBodyCacheQuota()
	if err != nil || (mode == "bytes" && full.AvailableBytes != 0) || (mode == "inodes" && full.AvailableNodes != 0) {
		t.Fatal("actual exhausted filesystem accounting", full, err)
	}
	digest := func() string {
		t.Helper()
		items, e := os.ReadDir(dir)
		if e != nil || len(items) != created {
			t.Fatal("retained quota contents disappeared", e, len(items))
		}
		h := sha256.New()
		for _, item := range items {
			f, e := os.OpenFile(filepath.Join(dir, item.Name()), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if e != nil {
				t.Fatal(e)
			}
			st, e := f.Stat()
			if e != nil || !st.Mode().IsRegular() {
				f.Close()
				t.Fatal("quota file identity changed", e)
			}
			fmt.Fprintf(h, "%s:%d:%o\n", item.Name(), st.Size(), st.Mode())
			if _, e := io.Copy(h, f); e != nil {
				f.Close()
				t.Fatal(e)
			}
			f.Close()
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	before := digest()
	if err := s.prepareApacheBodyStorage(context.Background(), cfg); err == nil {
		t.Fatal("exhausted hard quota did not refuse activation")
	}
	if after := digest(); after != before {
		t.Fatal("activation failure erased or changed retained contents", before, after)
	}
	proof := map[string]any{"passed": true, "mode": mode, "initial_budget": initial, "exhausted_budget": full, "actual_enospc": true, "non_sparse_bytes_written": written, "files_created": created, "retained_content_sha256": before, "activation_refused_without_cleanup": true, "caller_euid": os.Geteuid(), "caller_egid": os.Getegid(), "writer_uid": result.UID, "writer_effective_capabilities": result.Caps, "published_application_activation": false, "signed_application_receipt": false, "test_owned_tmpfs_contents_expire_at_unit_closure": true}
	b, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/run/panel-apache-body-cache24aid/quota-"+mode+".json", b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestApacheBodyCacheNativeUnprivilegedQuotaWriter(t *testing.T) {
	mode := os.Getenv("PANEL_QA_APACHE_BODY_QUOTA_WRITER")
	if mode == "" {
		t.Skip("only the actual private parent quota test may dispatch this writer")
	}
	if os.Geteuid() != 33 || os.Getegid() != 33 || (mode != "bytes" && mode != "inodes") {
		t.Fatal("actual fixed www-data identity required")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000\n") || !strings.Contains(string(status), "NoNewPrivs:\t1\n") {
		t.Fatal("writer retained capabilities or privilege escalation")
	}
	site := os.Getenv("PANEL_QA_APACHE_BODY_QUOTA_WRITER_SITE")
	if site == "" {
		site = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	}
	if site != "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" && site != apacheBodyConfigSiteA {
		t.Fatal("only the two fixed private quota fixture leaves are allowed")
	}
	dir := filepath.Join(apacheBodyTemporary, site)
	var initial syscall.Statfs_t
	if err := syscall.Statfs(dir, &initial); err != nil || initial.Bsize <= 0 || initial.Blocks*uint64(initial.Bsize) != apacheBodyCacheBytes || initial.Bavail*uint64(initial.Bsize) != apacheBodyCacheBytes || initial.Files != apacheBodyCacheInodes || initial.Ffree < apacheBodyCacheInodes-3 || initial.Ffree > apacheBodyCacheInodes-2 {
		t.Fatal("fresh fixed physical byte/inode budget required", err, initial)
	}
	created := 0
	written := int64(0)
	var exhaustion error
	if mode == "bytes" {
		f, err := os.OpenFile(filepath.Join(dir, "retained-real-quota-fill"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			t.Fatal(err)
		}
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = byte(i%251 + 1)
		}
		for written <= int64(apacheBodyCacheBytes) {
			n, e := f.Write(chunk)
			written += int64(n)
			if e != nil {
				exhaustion = e
				break
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		created = 1
		if written != int64(apacheBodyCacheBytes) {
			t.Fatal("non-sparse actually written bytes differ from the physical bound", written)
		}
	} else {
		for created <= int(apacheBodyCacheInodes) {
			f, e := os.OpenFile(filepath.Join(dir, fmt.Sprintf("retained-inode-%04d", created)), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
			if e != nil {
				exhaustion = e
				break
			}
			if e := f.Close(); e != nil {
				t.Fatal(e)
			}
			created++
		}
		if created != int(initial.Ffree) {
			t.Fatal("actual limited inode count differs", created)
		}
	}
	if !errors.Is(exhaustion, syscall.ENOSPC) {
		t.Fatal("kernel did not enforce actual ENOSPC", exhaustion)
	}
	b, err := json.Marshal(map[string]any{"written": written, "created": created, "enospc": true, "uid": os.Geteuid(), "cap_eff": "0000000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("QUOTA-WORKER " + string(b))
}
