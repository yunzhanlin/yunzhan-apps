//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Real SSH handshake + SFTP packets + actual ordinary files. The fixture server
// never accepts exec/shell/forwarding requests; it is not an external server or
// a replacement for the separate native OpenSSH integration acceptance.
type remoteSyncFixture struct {
	s                    *Service
	site                 string
	cfg                  remoteSyncConfig
	root, backup, secret string
	privateKey           []byte
	commands             atomic.Int32
	connections          sync.Map
	listener             net.Listener
}

func newRemoteSyncFixture(t *testing.T) *remoteSyncFixture {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("real non-root SFTP filesystem fixture must run as an unprivileged Linux user; root protocol fixtures cannot attest remote account scope")
	}
	if os.Getenv("PANEL_REMOTE_SYNC_NATIVE_SFTP_QA") != "1" {
		t.Skip("native OpenSSH SFTP fixture requires explicit owned QA opt-in")
	}
	host, e := os.ReadFile("/etc/hostname")
	if e != nil || (strings.TrimSpace(string(host)) != "lima-panel-ids24hj-clean-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-analytics23t-unit-debian13") {
		t.Fatal("native SFTP fixture restricted to owned QA hosts")
	}
	native := "/usr/lib/openssh/sftp-server"
	binary, e := os.ReadFile(native)
	if e != nil {
		t.Fatal("native OpenSSH SFTP server missing", e)
	}
	digest := sha256.Sum256(binary)
	if pin := os.Getenv("PANEL_REMOTE_SYNC_NATIVE_SFTP_SHA256"); len(pin) != 64 || hex.EncodeToString(digest[:]) != pin {
		t.Fatal("native SFTP executable does not match explicit fixture pin")
	}
	s, site, _ := appReliabilityFixture(t)
	base := t.TempDir()
	target := filepath.Join(base, "public")
	backup := filepath.Join(base, "private")
	for _, dir := range []string{target, backup} {
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	_, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(priv)
	if e != nil {
		t.Fatal(e)
	}
	f := &remoteSyncFixture{s: s, site: site, root: target, backup: backup, secret: "fixture-secret-never-report"}
	_, loginPrivate, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	loginSigner, e := ssh.NewSignerFromKey(loginPrivate)
	if e != nil {
		t.Fatal(e)
	}
	block, e := ssh.MarshalPrivateKey(loginPrivate, "owned fixture login")
	if e != nil {
		t.Fatal(e)
	}
	f.privateKey = pem.EncodeToMemory(block)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	f.listener = listener
	server := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != "fixture-user" || !bytes.Equal(password, []byte(f.secret)) {
			return nil, errors.New("fixture authentication rejected")
		}
		return nil, nil
	}}
	server.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() == "fixture-user" && bytes.Equal(key.Marshal(), loginSigner.PublicKey().Marshal()) {
			return nil, nil
		}
		return nil, errors.New("fixture key authentication rejected")
	}
	server.AddHostKey(signer)
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			f.connections.Store(raw, true)
			go func() {
				defer f.connections.Delete(raw)
				defer raw.Close()
				conn, channels, requests, e := ssh.NewServerConn(raw, server)
				if e != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for ch := range channels {
					if ch.ChannelType() != "session" {
						f.commands.Add(1)
						ch.Reject(ssh.Prohibited, "only sftp")
						continue
					}
					stream, reqs, e := ch.Accept()
					if e != nil {
						continue
					}
					go func() {
						defer stream.Close()
						for req := range reqs {
							var sub struct{ Name string }
							allowed := req.Type == "subsystem" && ssh.Unmarshal(req.Payload, &sub) == nil && sub.Name == "sftp"
							if !allowed {
								f.commands.Add(1)
								req.Reply(false, nil)
								continue
							}
							req.Reply(true, nil)
							// Real pinned OpenSSH native subsystem, under the same
							// unprivileged all-capabilities-zero fixture identity.
							cmd := exec.Command(native, "-e")
							cmd.Stdin = stream
							cmd.Stdout = stream
							_ = cmd.Run()
							return
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		clear(f.privateKey)
		listener.Close()
		f.connections.Range(func(key, value any) bool { key.(net.Conn).Close(); return true })
		if f.commands.Load() != 0 {
			t.Errorf("client attempted a non-SFTP command or channel: %d", f.commands.Load())
		}
	})
	port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])
	targetSpec := core.RemoteSyncTarget{Address: "127.0.0.1", Port: port, Username: "fixture-user", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), Root: target, BackupRoot: backup}
	in := core.AppModuleInput{RemoteTargetID: "fixture-target", RemoteTarget: &targetSpec, Password: f.secret, Enabled: true}
	if _, e = s.moduleRemoteSync(context.Background(), "save-remote", in); e != nil {
		t.Fatal(e)
	}
	f.cfg, e = s.readRemoteConfig(in.RemoteTargetID)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *remoteSyncFixture) queue(t *testing.T, id string) remoteSyncJob {
	t.Helper()
	in := core.AppModuleInput{SiteID: f.site, RemoteTargetID: f.cfg.ID, RemoteRequestID: id, ExpectedRevision: f.cfg.Revision}
	out, e := f.s.moduleRemoteSync(context.Background(), "queue-remote", in)
	if e != nil {
		t.Fatal(e)
	}
	public, ok := out.(map[string]any)["job"].(map[string]any)
	if !ok || public["remote_request_id"] != id || public["conflicts_count"] == nil {
		t.Fatal("queue did not return bounded public job identity")
	}
	j, e := f.s.readRemoteJob(id)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func (f *remoteSyncFixture) run(t *testing.T, id string) remoteSyncJob {
	t.Helper()
	f.queue(t, id)
	f.s.runOneRemoteSyncJob(context.Background())
	j, e := f.s.readRemoteJob(id)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func remoteFixtureWrite(t *testing.T, p, value string) {
	t.Helper()
	if e := os.WriteFile(p, []byte(value), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
}
func remoteFixtureRead(t *testing.T, p string) string {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestRemoteSyncEmptyQueuePinsSourceAndPersistenceFailure(t *testing.T) {
	for _, failQueue := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted-empty", true: "job-write-fails"}[failQueue], func(t *testing.T) {
			s, site, other := appReliabilityFixture(t)
			cfg := remoteSyncConfig{ID: "owned-empty", Revision: 1, SpecSHA: core.Hash("owned-empty-spec"), Enabled: true}
			expectQueueFailure := false
			if failQueue {
				jobs := filepath.Join(s.remoteSyncDir(), "jobs")
				if e := os.MkdirAll(jobs, 0700); e != nil {
					t.Fatal(e)
				}
				// Listing remains readable; only the later job publication fails.
				// A privileged test runner can bypass mode bits, so attest the
				// actual write refusal rather than confuse an early read failure.
				if e := os.Chmod(jobs, 0500); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { _ = os.Chmod(jobs, 0700) })
				probe := filepath.Join(jobs, "write-probe")
				f, e := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				expectQueueFailure = e != nil
				if e == nil {
					f.Close()
					if e = os.Remove(probe); e != nil {
						t.Fatal(e)
					}
				}
			}
			out, e := s.queueRemoteSync(cfg, core.AppModuleInput{SiteID: site, RemoteRequestID: core.ID(), ExpectedRevision: 1})
			if expectQueueFailure && e == nil || !expectQueueFailure && e != nil {
				t.Fatal("unexpected queue result", failQueue, e)
			}
			cp, e := s.readRemoteCheckpoint(cfg, site)
			if e != nil || cp.SiteID != site || len(cp.Files) != 0 || cp.Pending != nil {
				t.Fatal("empty source binding was not durable", cp, e)
			}
			if _, e := s.readRemoteCheckpoint(cfg, other); e == nil {
				t.Fatal("a different source silently reused an empty checkpoint")
			}
			if expectQueueFailure {
				t.Log("PASS actual job-write refusal after durable empty-source checkpoint")
			}
			if !expectQueueFailure {
				public := out.(map[string]any)["job"].(map[string]any)
				id := public["remote_request_id"].(string)
				if _, e = s.cancelRemoteSync(core.AppModuleInput{RemoteRequestID: id}); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = s.queueRemoteSync(cfg, core.AppModuleInput{SiteID: other, RemoteRequestID: core.ID(), ExpectedRevision: 1}); e == nil {
				t.Fatal("queue accepted a second source after empty acceptance or persistence failure")
			}
		})
	}
}

func TestRemoteSyncPolicyAndEncryptedAuthentication(t *testing.T) {
	f := newRemoteSyncFixture(t)
	for _, mutate := range []func(*core.RemoteSyncTarget){func(v *core.RemoteSyncTarget) { v.Address = "server.test" }, func(v *core.RemoteSyncTarget) { v.Address = "0.0.0.0" }, func(v *core.RemoteSyncTarget) { v.Username = "root" }, func(v *core.RemoteSyncTarget) { v.Root = "/etc/site" }, func(v *core.RemoteSyncTarget) { v.BackupRoot = v.Root + "/backup" }, func(v *core.RemoteSyncTarget) { v.HostKey = "" }, func(v *core.RemoteSyncTarget) { v.HostKey += "\n" + v.HostKey }, func(v *core.RemoteSyncTarget) { v.Root += "/../escape" }} {
		v := f.cfg.Target
		mutate(&v)
		if validateRemoteTarget(v) == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	plain, e := f.s.openRemoteAuth(f.cfg)
	if e != nil || string(plain) != f.secret {
		t.Fatal("authentication roundtrip", e)
	}
	clear(plain)
	record := remoteFixtureRead(t, f.s.remoteConfigPath(f.cfg.ID))
	if strings.Contains(record, f.secret) {
		t.Fatal("plaintext password persisted")
	}
	changed := f.cfg
	changed.ID = "another-target"
	if _, e = f.s.openRemoteAuth(changed); e == nil {
		t.Fatal("credential transferable between targets")
	}
	changed = f.cfg
	changed.SpecSHA = core.Hash("changed")
	if _, e = f.s.openRemoteAuth(changed); e == nil {
		t.Fatal("credential transferable between policies")
	}
	out, e := f.s.moduleRemoteSync(context.Background(), "remote-targets", core.AppModuleInput{})
	raw, _ := json.Marshal(out)
	if e != nil || strings.Contains(string(raw), "cipher") || strings.Contains(string(raw), f.secret) {
		t.Fatal("public report exposes credentials", e)
	}
	key := filepath.Join(f.s.remoteSyncDir(), "credential-key")
	saved := remoteFixtureRead(t, key)
	if e = os.Remove(key); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.openRemoteAuth(f.cfg); e == nil {
		t.Fatal("missing master key silently replaced")
	}
	if _, e = os.Lstat(key); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("replacement master key created")
	}
	if e = os.WriteFile(key, []byte(saved), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestRemoteSyncRealPrivateKeyAuthenticationAndCredentialRotation(t *testing.T) {
	f := newRemoteSyncFixture(t)
	original, e := os.ReadFile(f.s.remoteConfigPath(f.cfg.ID))
	if e != nil {
		t.Fatal(e)
	}
	in := core.AppModuleInput{RemoteTargetID: f.cfg.ID, RemoteTarget: &f.cfg.Target, RemotePrivateKey: string(f.privateKey), Enabled: true, ExpectedRevision: f.cfg.Revision}
	if _, e = f.s.moduleRemoteSync(context.Background(), "save-remote", in); e != nil {
		t.Fatal(e)
	}
	f.cfg, e = f.s.readRemoteConfig(f.cfg.ID)
	if e != nil || f.cfg.AuthKind != "private-key" || f.cfg.Revision != 2 {
		t.Fatal("private key rotation", e)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "key-authenticated")
	j := f.run(t, core.ID())
	if j.State != "succeeded" || remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "key-authenticated" {
		t.Fatal("actual public-key SSH authentication", j)
	}
	record := remoteFixtureRead(t, f.s.remoteConfigPath(f.cfg.ID))
	if strings.Contains(record, "PRIVATE KEY") || strings.Contains(record, string(f.privateKey)) || record == string(original) {
		t.Fatal("private key plaintext retained or rotation not persisted")
	}
	in.RemotePrivateKey = ""
	in.ExpectedRevision = 2
	beforeCipher := append([]byte{}, f.cfg.Cipher...)
	if _, e = f.s.moduleRemoteSync(context.Background(), "save-remote", in); e != nil {
		t.Fatal(e)
	}
	fresh, e := f.s.readRemoteConfig(f.cfg.ID)
	if e != nil || fresh.Revision != 3 || !bytes.Equal(beforeCipher, fresh.Cipher) {
		t.Fatal("blank credential did not retain prior encrypted auth", e)
	}
	t.Log("PASS actual SSH public-key authentication, context-bound encrypted private key and non-destructive credential rotation")
}

func TestRemoteSyncUninstallPreflightKeepsPendingWorkAndEvidence(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "one")
	id := core.ID()
	f.queue(t, id)
	if e := f.s.appModuleLifecycle(context.Background(), "files-sync", "uninstall", nil, func(string) {}); e == nil || !f.s.moduleInstalled("files-sync") {
		t.Fatal("uninstall discarded an active queue")
	}
	if _, e := f.s.cancelRemoteSync(core.AppModuleInput{RemoteRequestID: id}); e != nil {
		t.Fatal(e)
	}
	if e := f.s.appModuleLifecycle(context.Background(), "files-sync", "uninstall", nil, func(string) {}); e != nil || f.s.moduleInstalled("files-sync") {
		t.Fatal("cancelled queue prevented safe uninstall", e)
	}
	if _, e := f.s.readRemoteConfig(f.cfg.ID); e != nil {
		t.Fatal("uninstall deleted encrypted connection", e)
	}
	if _, e := f.s.readRemoteJob(id); e != nil {
		t.Fatal("uninstall deleted persistent evidence", e)
	}
	if e := moduleWrite(filepath.Join(f.s.moduleDir("files-sync"), "installed.json"), map[string]string{"id": "files-sync"}); e != nil {
		t.Fatal(e)
	}
	cp, _, _ := prepareRemoteInterruptedFixture(t, f)
	if cp.Pending == nil {
		t.Fatal("fixture pending missing")
	}
	if e := f.s.appModuleLifecycle(context.Background(), "files-sync", "uninstall", nil, func(string) {}); e == nil || !f.s.moduleInstalled("files-sync") {
		t.Fatal("uninstall abandoned pending remote file handoff")
	}
}
func TestRemoteSyncRealSSHIncrementalConflictsAndReplay(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "one")
	fixtureWrite(t, f.s, f.site, "conflict.txt", "source")
	remoteFixtureWrite(t, filepath.Join(f.root, "conflict.txt"), "user")
	remoteFixtureWrite(t, filepath.Join(f.root, "extra.txt"), "keep")
	in := core.AppModuleInput{SiteID: f.site, RemoteTargetID: f.cfg.ID, RemoteRequestID: core.ID(), ExpectedRevision: f.cfg.Revision}
	preview, e := f.s.moduleRemoteSync(context.Background(), "remote-preview", in)
	if e != nil || moduleCount(preview.(map[string]any), "copied") != 1 || moduleCount(preview.(map[string]any), "conflicts") != 1 {
		t.Fatal("preview", e, preview)
	}
	if _, e = os.Stat(filepath.Join(f.root, "copy.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("preview wrote target")
	}
	f.queue(t, in.RemoteRequestID)
	out, e := f.s.moduleRemoteSync(context.Background(), "queue-remote", in)
	if e != nil || out.(map[string]any)["replayed"] != true {
		t.Fatal("durable replay failed", e)
	}
	changed := in
	changed.Excludes = []string{"copy.txt"}
	if _, e = f.s.moduleRemoteSync(context.Background(), "queue-remote", changed); e == nil {
		t.Fatal("same job reused for altered payload")
	}
	f.s.runOneRemoteSyncJob(context.Background())
	j, e := f.s.readRemoteJob(in.RemoteRequestID)
	if e != nil || j.State != "conflicts" || j.Copied != 1 || len(j.Conflicts) != 1 {
		t.Fatal("actual SSH job", e, j)
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "one" || remoteFixtureRead(t, filepath.Join(f.root, "conflict.txt")) != "user" || remoteFixtureRead(t, filepath.Join(f.root, "extra.txt")) != "keep" {
		t.Fatal("user files overwritten")
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "two")
	j = f.run(t, core.ID())
	if j.Copied != 1 || j.State != "conflicts" {
		t.Fatal("incremental update", j)
	}
	files, e := filepath.Glob(filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, "*", "previous"))
	if e != nil || len(files) != 1 || remoteFixtureRead(t, files[0]) != "one" {
		t.Fatal("old bytes not privately retained", e, files)
	}
	remoteFixtureWrite(t, filepath.Join(f.root, "copy.txt"), "external")
	fixtureWrite(t, f.s, f.site, "copy.txt", "three")
	j = f.run(t, core.ID())
	if j.Copied != 0 || len(j.Conflicts) != 2 || remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "external" {
		t.Fatal("changed tracked target overwritten", j)
	}
	if f.commands.Load() != 0 {
		t.Fatal("shell channel attempted")
	}
	t.Log("PASS actual SSH/SFTP packets, incremental files, private old-byte backup, external conflict and durable task replay")
}
func TestRemoteSyncHostKeyAndPathRefusal(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "safe.txt", "safe")
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(private)
	changed := f.cfg
	changed.Target.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))
	changed.SpecSHA = remoteSpecSHA(changed.Target)
	changed.Cipher, _ = f.s.sealRemoteAuth(changed, []byte(f.secret))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, e := f.s.dialRemoteSync(ctx, changed); e == nil {
		c.Close()
		t.Fatal("unknown host key trusted")
	}
	if e := os.Symlink(f.backup, filepath.Join(f.root, "linked")); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(f.s.Config.SitesDir, f.site, "public", "linked"), 0755); e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, f.s, f.site, "linked/secret.txt", "noescape")
	j := f.run(t, core.ID())
	if j.State != "failed" || j.Copied != 0 {
		t.Fatal("linked remote parent accepted", j)
	}
	if _, e := os.Stat(filepath.Join(f.backup, "secret.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("write escaped target")
	}
	if e := os.Remove(filepath.Join(f.root, "linked")); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(f.backup, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.moduleRemoteSync(context.Background(), "probe-remote", core.AppModuleInput{RemoteTargetID: f.cfg.ID}); e == nil {
		t.Fatal("public backup directory accepted")
	}
}
func TestRemoteSyncUninstallCancellationAndStaleRevision(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "one")
	id := core.ID()
	f.queue(t, id)
	if _, e := f.s.cancelRemoteSync(core.AppModuleInput{RemoteRequestID: id}); e != nil {
		t.Fatal(e)
	}
	f.s.runOneRemoteSyncJob(context.Background())
	j, _ := f.s.readRemoteJob(id)
	if j.State != "failed" || j.Copied != 0 {
		t.Fatal("cancelled queued job ran", j)
	}
	second := core.ID()
	f.queue(t, second)
	f.cfg.Revision++
	if e := moduleWrite(f.s.remoteConfigPath(f.cfg.ID), f.cfg); e != nil {
		t.Fatal(e)
	}
	f.s.runOneRemoteSyncJob(context.Background())
	j, _ = f.s.readRemoteJob(second)
	if j.State != "failed" || j.Copied != 0 {
		t.Fatal("stale revision ran", j)
	}
	third := core.ID()
	f.queue(t, third)
	if e := os.Remove(filepath.Join(f.s.moduleDir("files-sync"), "installed.json")); e != nil {
		t.Fatal(e)
	}
	f.s.runOneRemoteSyncJob(context.Background())
	j, _ = f.s.readRemoteJob(third)
	if j.State != "queued" || j.Copied != 0 {
		t.Fatal("uninstalled module executed queue", j)
	}
	if _, e := os.Stat(filepath.Join(f.root, "copy.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("cancel/stale/uninstall wrote target")
	}
}

func prepareRemoteInterruptedFixture(t *testing.T, f *remoteSyncFixture) (remoteSyncCheckpoint, string, string) {
	t.Helper()
	fixtureWrite(t, f.s, f.site, "copy.txt", "old")
	first := f.run(t, core.ID())
	if first.State != "succeeded" {
		t.Fatal(first)
	}
	cp, e := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if e != nil {
		t.Fatal(e)
	}
	old := cp.Files["copy.txt"]
	j := remoteSyncJob{ID: core.ID(), TargetID: f.cfg.ID, SiteID: f.site, Revision: f.cfg.Revision, SpecSHA: f.cfg.SpecSHA, Excludes: []string{}, State: "interrupted", CreatedAt: core.Now(), Conflicts: []string{}}
	p := remoteSyncPending{ID: core.ID(), JobID: j.ID, Path: "copy.txt", Old: &old, New: moduleFile{SHA: core.Hash("new"), Size: 3, Mode: 0644}}
	cp.Pending = &p
	dir, staged, previous := remoteTransactionPaths(f.cfg, p)
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	remoteFixtureWrite(t, staged, "new")
	if e = os.Rename(filepath.Join(f.root, p.Path), previous); e != nil {
		t.Fatal(e)
	}
	if e = moduleWrite(f.s.remoteJobPath(j.ID), j); e != nil {
		t.Fatal(e)
	}
	if e = moduleWrite(f.s.remoteCheckpointPath(f.cfg.ID), cp); e != nil {
		t.Fatal(e)
	}
	return cp, staged, previous
}
func TestRemoteSyncRecoveryRollbackAndCommit(t *testing.T) {
	f := newRemoteSyncFixture(t)
	cp, staged, previous := prepareRemoteInterruptedFixture(t, f)
	out, e := f.s.recoverRemoteSync(context.Background(), f.cfg)
	if e != nil || out.(map[string]any)["outcome"] != "rolled-back" || remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "old" {
		t.Fatal("rollback", e, out)
	}
	if remoteFixtureRead(t, staged) != "new" || remoteFixtureRead(t, previous) != "old" {
		t.Fatal("recovery erased evidence")
	}
	if e = os.Remove(filepath.Join(f.root, "copy.txt")); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(staged, filepath.Join(f.root, "copy.txt")); e != nil {
		t.Fatal(e)
	}
	if e = moduleWrite(f.s.remoteCheckpointPath(f.cfg.ID), cp); e != nil {
		t.Fatal(e)
	}
	out, e = f.s.recoverRemoteSync(context.Background(), f.cfg)
	if e != nil || out.(map[string]any)["outcome"] != "committed" {
		t.Fatal("commit recovery", e, out)
	}
	after, e := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if e != nil || after.Pending != nil || after.Files["copy.txt"].SHA != core.Hash("new") {
		t.Fatal("checkpoint not finalized", e)
	}
	t.Log("PASS actual SFTP recovery of moved old file and published new file without overwriting destination; retained private evidence")
}
func TestRemoteSyncRecoveryPreservesExternalTarget(t *testing.T) {
	f := newRemoteSyncFixture(t)
	cp, _, previous := prepareRemoteInterruptedFixture(t, f)
	remoteFixtureWrite(t, filepath.Join(f.root, "copy.txt"), "external")
	if _, e := f.s.recoverRemoteSync(context.Background(), f.cfg); e == nil {
		t.Fatal("unrecognized target overwritten")
	}
	after, e := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if e != nil || after.Pending == nil || after.Pending.ID != cp.Pending.ID || remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "external" || remoteFixtureRead(t, previous) != "old" {
		t.Fatal("evidence or user target lost", e)
	}
}
func TestRemoteSyncNoOverwritePublicationAndCheckpointRefusal(t *testing.T) {
	f := newRemoteSyncFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, e := f.s.dialRemoteSync(ctx, f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	remoteFixtureWrite(t, filepath.Join(f.root, "exists.txt"), "user")
	staged := filepath.Join(f.backup, "fixture-staged")
	remoteFixtureWrite(t, staged, "new")
	if e = conn.client.Link(staged, filepath.Join(f.root, "exists.txt")); e == nil {
		t.Fatal("hardlink overwrote existing target")
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "exists.txt")) != "user" {
		t.Fatal("existing bytes lost")
	}
	checkpoint := f.s.remoteCheckpointPath(f.cfg.ID)
	if e = moduleWrite(checkpoint, map[string]any{"corrupt": true}); e != nil {
		t.Fatal(e)
	}
	before := remoteFixtureRead(t, checkpoint)
	fixtureWrite(t, f.s, f.site, "copy.txt", "safe")
	if _, e = f.s.queueRemoteSync(f.cfg, core.AppModuleInput{SiteID: f.site, RemoteRequestID: core.ID(), ExpectedRevision: f.cfg.Revision}); e == nil {
		t.Fatal("corrupt checkpoint overwritten")
	}
	if remoteFixtureRead(t, checkpoint) != before {
		t.Fatal("corrupt evidence altered")
	}
	if e = os.Chmod(checkpoint, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.readRemoteCheckpoint(f.cfg, f.site); e == nil {
		t.Fatal("public checkpoint accepted")
	}
}

func TestRemoteSyncTrueSIGKILLAfterOldFileMoved(t *testing.T) {
	if payload := os.Getenv("PANEL_REMOTE_SYNC_KILL_CHILD"); payload != "" {
		var input struct {
			SitesDir    string        `json:"sites_dir"`
			SecurityDir string        `json:"security_dir"`
			Job         remoteSyncJob `json:"job"`
		}
		if e := json.Unmarshal([]byte(payload), &input); e != nil {
			t.Fatal(e)
		}
		s := New(Config{SitesDir: input.SitesDir, SecurityDir: input.SecurityDir})
		cfg, e := s.readRemoteConfig(input.Job.TargetID)
		if e != nil {
			t.Fatal(e)
		}
		cp, e := s.readRemoteCheckpoint(cfg, input.Job.SiteID)
		if e != nil {
			t.Fatal(e)
		}
		old := cp.Files["copy.txt"]
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		conn, e := s.dialRemoteSync(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		owner, e := remoteRoots(conn.client, cfg)
		if e != nil {
			t.Fatal(e)
		}
		checks := 0
		guard := func() error {
			checks++
			if checks == 3 {
				fmt.Fprintln(os.Stdout, "OWN_REMOTE_OLD_MOVED_READY_FOR_SIGKILL")
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}
		if e = s.commitRemoteFile(ctx, conn.client, cfg, &cp, input.Job, "copy.txt", []byte("new"), moduleFile{SHA: core.Hash("new"), Size: 3, Mode: 0644}, &old, owner, guard); e != nil {
			t.Fatal(e)
		}
		t.Fatal("child completed without requested kill")
	}
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "old")
	first := f.run(t, core.ID())
	if first.State != "succeeded" {
		t.Fatal(first)
	}
	j := remoteSyncJob{ID: core.ID(), TargetID: f.cfg.ID, SiteID: f.site, Revision: f.cfg.Revision, SpecSHA: f.cfg.SpecSHA, Excludes: []string{}, State: "running", CreatedAt: core.Now(), Conflicts: []string{}}
	if e := moduleWrite(f.s.remoteJobPath(j.ID), j); e != nil {
		t.Fatal(e)
	}
	input := struct {
		SitesDir    string        `json:"sites_dir"`
		SecurityDir string        `json:"security_dir"`
		Job         remoteSyncJob `json:"job"`
	}{SitesDir: f.s.Config.SitesDir, SecurityDir: f.s.Config.SecurityDir, Job: j}
	payload, e := json.Marshal(input)
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRemoteSyncTrueSIGKILLAfterOldFileMoved$", "-test.v", "-test.timeout=70s")
	child.Env = append(os.Environ(), "PANEL_REMOTE_SYNC_KILL_CHILD="+string(payload))
	stdout, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	finished := false
	t.Cleanup(func() {
		if !finished {
			child.Process.Kill()
			child.Wait()
		}
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "OWN_REMOTE_OLD_MOVED_READY_FOR_SIGKILL" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not reach actual old-file move", stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child did not report transaction boundary")
	}
	if _, e = os.Lstat(filepath.Join(f.root, "copy.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("old file not actually moved before kill")
	}
	cp, e := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if e != nil || cp.Pending == nil || cp.Pending.JobID != j.ID {
		t.Fatal("durable pending transaction missing", e)
	}
	_, staged, previous := remoteTransactionPaths(f.cfg, *cp.Pending)
	if remoteFixtureRead(t, previous) != "old" || remoteFixtureRead(t, staged) != "new" {
		t.Fatal("actual remote transaction bytes absent")
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	e = child.Wait()
	finished = true
	var exit *exec.ExitError
	if !errors.As(e, &exit) {
		t.Fatal("child did not die by signal", e)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("not a true SIGKILL", exit)
	}
	restarted := New(f.s.Config)
	workerCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); restarted.runRemoteSyncWorker(workerCtx) }()
	defer func() { stop(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		restarted.mu.Lock()
		record, e := restarted.readRemoteJob(j.ID)
		restarted.mu.Unlock()
		if e == nil && record.State == "interrupted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restart did not safely pause running task", e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	restarted.mu.Lock()
	out, e := restarted.recoverRemoteSync(context.Background(), f.cfg)
	restarted.mu.Unlock()
	if e != nil || out.(map[string]any)["outcome"] != "rolled-back" || remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "old" {
		t.Fatal("true-kill rollback", e, out)
	}
	if remoteFixtureRead(t, previous) != "old" || remoteFixtureRead(t, staged) != "new" {
		t.Fatal("true-kill recovery erased evidence")
	}
	t.Log("PASS true SIGKILL after actual OpenSSH SFTP old-file move; durable journal, startup pause and no-overwrite recovery restored old bytes")
}

func TestRemoteSyncBackgroundQueueAndUninstall(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "one")
	id := core.ID()
	f.queue(t, id)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.s.runRemoteSyncWorker(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(12 * time.Second)
	for {
		f.s.mu.Lock()
		j, e := f.s.readRemoteJob(id)
		f.s.mu.Unlock()
		if e == nil && j.State == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual 5-second worker did not finish persistent queue", e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "one" {
		t.Fatal("worker did not transfer real bytes")
	}
	f.s.mu.Lock()
	if e := os.Remove(filepath.Join(f.s.moduleDir("files-sync"), "installed.json")); e != nil {
		f.s.mu.Unlock()
		t.Fatal(e)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "two")
	next := core.ID()
	f.queue(t, next)
	f.s.mu.Unlock()
	time.Sleep(6 * time.Second)
	f.s.mu.Lock()
	j, e := f.s.readRemoteJob(next)
	f.s.mu.Unlock()
	if e != nil || j.State != "queued" || remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "one" {
		t.Fatal("uninstalled module background worker wrote target", e, j)
	}
	t.Log("PASS real background interval transferred queued bytes without a browser; uninstall marker stopped subsequent remote task")
}

func TestRemoteSyncDirectoryInputBudgetAndBoundedJobReports(t *testing.T) {
	f := newRemoteSyncFixture(t)
	dir := filepath.Join(f.backup, "bounded-directory")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 513; i++ {
		if e := os.WriteFile(filepath.Join(dir, fmt.Sprintf("entry-%04d", i)), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, e := f.s.dialRemoteSync(ctx, f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = conn.client.ReadDir(dir); e == nil {
		conn.Close()
		t.Fatal("oversized native SFTP directory listing accepted")
	}
	conn.Close()
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 513 {
		t.Fatal("listing refusal modified remote directory", e)
	}
	a, b := net.Pipe()
	defer b.Close()
	reader := remoteSyncReader{Reader: strings.NewReader("over-budget"), raw: a, total: 64, listing: true, metadata: 2}
	buffer := make([]byte, 16)
	if _, e = reader.Read(buffer); e == nil {
		a.Close()
		t.Fatal("metadata wire budget did not fail closed")
	}
	j := remoteSyncJob{ID: core.ID(), TargetID: f.cfg.ID, SiteID: f.site, Revision: f.cfg.Revision, SpecSHA: f.cfg.SpecSHA, Excludes: []string{}, State: "conflicts", CreatedAt: core.Now(), Conflicts: []string{}}
	for i := 0; i < 1000; i++ {
		j.Conflicts = append(j.Conflicts, fmt.Sprintf("conflict-%04d.txt", i))
	}
	if e = moduleWrite(f.s.remoteJobPath(j.ID), j); e != nil {
		t.Fatal(e)
	}
	report, e := f.s.remoteJobReport(core.AppModuleInput{RemoteRequestID: j.ID})
	if e != nil {
		t.Fatal(e)
	}
	public := report.(map[string]any)["job"].(map[string]any)
	if len(public["conflicts"].([]string)) != 200 || public["conflicts_count"] != 1000 || public["report_limited"] != true {
		t.Fatal("job report not bounded", public)
	}
	// A repeated submission is also a read of the original durable job. It
	// must use exactly the same bounded projection as the details endpoint.
	replayed, e := f.s.queueRemoteSync(f.cfg, core.AppModuleInput{SiteID: f.site, RemoteRequestID: j.ID, ExpectedRevision: f.cfg.Revision})
	if e != nil {
		t.Fatal(e)
	}
	row := replayed.(map[string]any)["job"].(map[string]any)
	if replayed.(map[string]any)["replayed"] != true || !reflect.DeepEqual(row, public) {
		t.Fatal("replay exposed unbounded/private job fields", row)
	}
	for _, key := range []string{"excludes", "spec_sha256"} {
		if _, exists := row[key]; exists {
			t.Fatal("private job field exposed", key)
		}
	}
	for _, in := range []core.AppModuleInput{{Limit: 33}, {Offset: 129}, {Limit: -1}} {
		if _, e = f.s.remoteJobReport(in); e == nil {
			t.Fatal("oversized job page accepted")
		}
	}
	t.Log("PASS real native SFTP 513-entry listing refusal, decrypted metadata input budget and bounded conflict/task reporting")
}
