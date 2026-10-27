package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

const MaxAccountChildPermitBytes = 4096
const AccountChildPermitLifetime = 2 * time.Minute

var ErrAccountChildPermit = errors.New("TCP/UDP 原始账号子进程、父租约或启动窗口无法核对；保留记录，不接管或重放")
var accountPermitBoot = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PRIVATE serialization, not RPC input or effect authority. A future Root child
// must independently observe the real kernel/unit/lease and current Core grant,
// verify the compiled signing key, and exclusively retain its attempt BEFORE
// invoking a fixed OS command. Fabricating matching structs grants nothing.
type AccountChildPermit struct {
	Format                int    `json:"format"`
	AppVersion            string `json:"app_version"`
	JobID                 string `json:"job_id"`
	ActorID               string `json:"actor_id"`
	Nonce                 string `json:"nonce"`
	BootID                string `json:"boot_id"`
	ParentPID             uint32 `json:"parent_pid"`
	ParentStartTicks      uint64 `json:"parent_start_ticks"`
	ParentExeSHA256       string `json:"parent_exe_sha256"`
	ProgrammeInputsSHA256 string `json:"programme_inputs_sha256"`
	SeedSHA256            string `json:"seed_sha256"`
	AccountIntentSHA256   string `json:"account_intent_sha256"`
	JournalDevice         uint64 `json:"journal_device"`
	JournalInode          uint64 `json:"journal_inode"`
	RunLockDevice         uint64 `json:"run_lock_device"`
	RunLockInode          uint64 `json:"run_lock_inode"`
	CreatedAt             string `json:"created_at"`
}

func AccountParentUnit(job string) (string, error) {
	if !operationID.MatchString(job) {
		return "", ErrAccountChildPermit
	}
	return "panel-lbstream-install@" + job + ".service", nil
}
func AccountCreationUnit(job string) (string, error) {
	if !operationID.MatchString(job) {
		return "", ErrAccountChildPermit
	}
	return "panel-lbstream-account-create@" + job + ".service", nil
}
func validAccountChildPermit(p AccountChildPermit) bool {
	if p.Format != 1 || p.AppVersion != AppVersion || !operationID.MatchString(p.JobID) || !operationID.MatchString(p.ActorID) || !operationID.MatchString(p.Nonce) ||
		!accountPermitBoot.MatchString(p.BootID) || p.BootID == "00000000-0000-0000-0000-000000000000" || p.ParentPID <= 1 || p.ParentPID > 2147483647 || p.ParentStartTicks == 0 ||
		p.JournalDevice == 0 || p.JournalInode == 0 || p.RunLockDevice == 0 || p.RunLockInode == 0 {
		return false
	}
	for _, h := range []string{p.ParentExeSHA256, p.ProgrammeInputsSHA256, p.SeedSHA256, p.AccountIntentSHA256} {
		if !operationHash(h) {
			return false
		}
	}
	stamp, err := time.Parse(time.RFC3339, p.CreatedAt)
	return err == nil && stamp.Year() >= 2026 && stamp.UTC().Format(time.RFC3339) == p.CreatedAt
}
func AccountChildPermitBytes(p AccountChildPermit) ([]byte, error) {
	if !validAccountChildPermit(p) {
		return nil, ErrAccountChildPermit
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) >= MaxAccountChildPermitBytes {
		return nil, ErrAccountChildPermit
	}
	return append(raw, '\n'), nil
}
func DecodeAccountChildPermit(raw []byte) (AccountChildPermit, error) {
	var p AccountChildPermit
	if len(raw) == 0 || len(raw) > MaxAccountChildPermitBytes || json.Unmarshal(raw, &p) != nil {
		return AccountChildPermit{}, ErrAccountChildPermit
	}
	canonical, err := AccountChildPermitBytes(p)
	if err != nil || !bytes.Equal(raw, canonical) {
		return AccountChildPermit{}, ErrAccountChildPermit
	}
	return p, nil
}
func AccountChildPermitBindsSeed(p AccountChildPermit, seedRaw []byte) bool {
	seed, err := DecodeInstallationSeed(seedRaw)
	return err == nil && validAccountChildPermit(p) && p.JobID == seed.JobID && p.ActorID == seed.ActorID && p.Nonce == seed.Nonce && p.AppVersion == seed.AppVersion &&
		p.ProgrammeInputsSHA256 == seed.ProgrammeInputsSHA256 && p.SeedSHA256 == serviceDigest(seedRaw)
}

// These are kernel/unit/held-file observations, NEVER trusted client claims.
// This pure equality predicate does not open /proc, pin a pidfd or create users.
type AccountParentObservation struct {
	BootID                                                                              string
	PID                                                                                 uint32
	StartTicks                                                                          uint64
	ExeSHA256, ProgrammeInputsSHA256, SeedSHA256, AccountIntentSHA256                   string
	Unit, ControlGroup, ProcessControlGroup, ChildUnit                                  string
	UID, GID                                                                            uint32
	NoNewPrivileges, ActiveRunning, ExclusiveRunLock, RunLockReadWrite, RunLockOrdinary bool
	RunLockOwnerPID                                                                     uint32
	JournalDevice, JournalInode, RunLockDevice, RunLockInode                            uint64
	RunLockUID, RunLockGID, RunLockMode, RunLockLinks                                   uint32
	RunLockBytes                                                                        int64
	JournalPhase                                                                        string
}

func AccountChildParentMatches(p AccountChildPermit, o AccountParentObservation, now time.Time) bool {
	if !validAccountChildPermit(p) || now.IsZero() {
		return false
	}
	created, _ := time.Parse(time.RFC3339, p.CreatedAt)
	if now.Before(created) || now.Sub(created) > AccountChildPermitLifetime {
		return false
	}
	parent, _ := AccountParentUnit(p.JobID)
	child, _ := AccountCreationUnit(p.JobID)
	// Future fixed templates must explicitly use Slice=system.slice. An
	// unexpected unit/cgroup layout is a refusal, not an alias or a fallback.
	group := "/system.slice/" + parent
	return o.BootID == p.BootID && o.PID == p.ParentPID && o.StartTicks == p.ParentStartTicks && o.ExeSHA256 == p.ParentExeSHA256 &&
		o.ProgrammeInputsSHA256 == p.ProgrammeInputsSHA256 && o.SeedSHA256 == p.SeedSHA256 && o.AccountIntentSHA256 == p.AccountIntentSHA256 &&
		o.Unit == parent && o.ChildUnit == child && o.ControlGroup == group && o.ProcessControlGroup == group && o.UID == 0 && o.GID == 0 && o.NoNewPrivileges && o.ActiveRunning &&
		o.ExclusiveRunLock && o.RunLockReadWrite && o.RunLockOrdinary && o.RunLockOwnerPID == p.ParentPID && o.RunLockUID == 0 && o.RunLockGID == 0 && o.RunLockMode == 0600 && o.RunLockLinks == 1 && o.RunLockBytes == 0 &&
		o.JournalDevice == p.JournalDevice && o.JournalInode == p.JournalInode && o.RunLockDevice == p.RunLockDevice && o.RunLockInode == p.RunLockInode && o.JournalPhase == "account-intent" &&
		!strings.ContainsAny(o.Unit+o.ChildUnit, "\x00\r\n")
}
