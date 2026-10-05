package core

import (
	"encoding/base32"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOTPStandardVectorsAndWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := hotp(secret, uint64(i), 6); got != want {
			t.Fatalf("RFC4226 %d got %s", i, got)
		}
	}
	for _, v := range []struct {
		seconds int64
		want    string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := hotp(secret, uint64(v.seconds/30), 8); got != v.want {
			t.Fatalf("RFC6238 %d got %s", v.seconds, got)
		}
	}
	now := time.Unix(1234567890, 0)
	step := now.Unix() / 30
	for _, offset := range []int64{-1, 0, 1} {
		code := hotp(secret, uint64(step+offset), 6)
		if _, e := totpStep(secret, code, now, -1); e != nil {
			t.Fatal(e)
		}
		if _, e := totpStep(secret, code, now, step+offset); e == nil {
			t.Fatal("OTP replay accepted")
		}
	}
	for _, code := range []string{"12", "12345678", "１２３４５６", hotp(secret, uint64(step-2), 6), hotp(secret, uint64(step+2), 6)} {
		if _, e := totpStep(secret, code, now, -1); e == nil {
			t.Fatal("out of window OTP accepted")
		}
	}
}
func TestAccountSecretEncryptionIdentityAndMissingKey(t *testing.T) {
	s := testStore(t)
	dir := t.TempDir()
	key, e := s.accountKey(dir)
	if e != nil {
		t.Fatal(e)
	}
	raw, text, e := newTOTPSecret()
	if e != nil {
		t.Fatal(e)
	}
	encrypted, e := encryptAccountSecret(key, "first", raw)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(encrypted), text) || strings.Contains(string(encrypted), string(raw)) {
		t.Fatal("plaintext secret retained")
	}
	if _, e = decryptAccountSecret(key, "second", encrypted); e == nil {
		t.Fatal("ciphertext crossed account")
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, e = decryptAccountSecret(key, "first", encrypted); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	s.DB.Exec(`INSERT INTO users VALUES('id','admin',?,?)`, hash, Now())
	s.DB.Exec(`INSERT INTO account_security(user_id,pending_secret) VALUES('id',?)`, encrypted)
	if e = os.Remove(filepath.Join(dir, "credential-key")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.accountKey(dir); e == nil {
		t.Fatal("missing encryption key silently replaced")
	}
}
func accountFixture(t *testing.T) (*Store, []byte, accountSession, time.Time) {
	t.Helper()
	s := testStore(t)
	h, e := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, ID(), "admin", h, Now()); e != nil {
		t.Fatal(e)
	}
	key, e := s.accountKey(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1788849000, 0)
	session, e := s.authenticateAccount("admin", "test-password-long", "", key, now)
	if e != nil {
		t.Fatal(e)
	}
	return s, key, session, now
}
func TestAccountProfileEmailAndPasswordAreAtomic(t *testing.T) {
	s, key, session, now := accountFixture(t)
	for _, invalid := range []string{"name <admin@example.com>", "invalid", strings.Repeat("a", 256) + "@example.com"} {
		if _, e := s.changeAccount("profile", Hash(session.Token), session.CSRF, accountInput{Password: "test-password-long", Email: invalid}, key, now); e == nil {
			t.Fatalf("accepted invalid email %q", invalid)
		}
	}
	result, e := s.changeAccount("profile", Hash(session.Token), session.CSRF, accountInput{Password: "test-password-long", NewPassword: "new-password-long", Email: "admin@example.com"}, key, now)
	if e != nil {
		t.Fatal(e)
	}
	var email string
	if e = s.DB.QueryRow(`SELECT email FROM account_profiles`).Scan(&email); e != nil || email != "admin@example.com" {
		t.Fatalf("email not saved: %q %v", email, e)
	}
	if _, e = s.authenticateAccount("admin", "test-password-long", "", key, now); e == nil {
		t.Fatal("old password remained valid")
	}
	if _, e = s.authenticateAccount("admin", "new-password-long", "", key, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.changeAccount("profile", Hash(session.Token), session.CSRF, accountInput{Password: "new-password-long", Email: ""}, key, now); e == nil {
		t.Fatal("previous session remained valid")
	}
	if result.Token == "" || result.CSRF == "" {
		t.Fatal("profile did not rotate session")
	}
}
func TestAccountMFARecoveryAndSessionTransactions(t *testing.T) {
	s, key, session, now := accountFixture(t)
	change := func(action string, sess accountSession, code, newPassword string) (accountResult, error) {
		return s.changeAccount(action, Hash(sess.Token), sess.CSRF, accountInput{Password: "test-password-long", Code: code, NewPassword: newPassword}, key, now)
	}
	setup, e := change("setup", session, "", "")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if e != nil {
		t.Fatal(e)
	}
	if setup.ExpiresAt != now.Add(10*time.Minute).Unix() {
		t.Fatal("setup expiry")
	}
	// Pending setup must not alter password-only login.
	second, e := s.authenticateAccount("admin", "test-password-long", "", key, now)
	if e != nil {
		t.Fatal(e)
	}
	enabled, e := change("confirm", session, hotp(raw, uint64(now.Unix()/30), 6), "")
	if e != nil || len(enabled.RecoveryCodes) != 10 {
		t.Fatal(e)
	}
	if _, e = change("disable", second, "", ""); e == nil {
		t.Fatal("prior session survived MFA activation")
	}
	if _, e = s.authenticateAccount("admin", "test-password-long", "", key, now); e == nil {
		t.Fatal("password bypassed MFA")
	}
	if _, e = s.authenticateAccount("admin", "test-password-long", hotp(raw, uint64(now.Unix()/30), 6), key, now); e == nil {
		t.Fatal("setup OTP reused for login")
	}
	firstCode := enabled.RecoveryCodes[0]
	if _, e = s.authenticateAccount("admin", "wrong password", firstCode, key, now); e == nil {
		t.Fatal("wrong password accepted")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if _, e := s.authenticateAccount("admin", "test-password-long", firstCode, key, now); e == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("recovery code concurrent usage", wins.Load())
	}
	now = now.Add(30 * time.Second)
	otp := hotp(raw, uint64(now.Unix()/30), 6)
	logged, e := s.authenticateAccount("admin", "test-password-long", otp, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.authenticateAccount("admin", "test-password-long", otp, key, now); !errors.Is(e, errCredentials) {
		t.Fatal("OTP reused", e)
	}
	changed, e := change("password", logged, enabled.RecoveryCodes[1], "changed-password-long")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = change("disable", logged, enabled.RecoveryCodes[2], ""); e == nil {
		t.Fatal("old session changed security")
	}
	if _, e = s.authenticateAccount("admin", "test-password-long", enabled.RecoveryCodes[2], key, now); e == nil {
		t.Fatal("old password still accepted")
	}
	// This recovery code remains valid because the wrong password never consumes it.
	final, e := s.authenticateAccount("admin", "changed-password-long", enabled.RecoveryCodes[2], key, now)
	if e != nil {
		t.Fatal(e)
	}
	out, e := s.changeAccount("disable", Hash(final.Token), final.CSRF, accountInput{Password: "changed-password-long", Code: enabled.RecoveryCodes[3]}, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if out.Token == changed.Token {
		t.Fatal("session not rotated")
	}
	if _, e = s.authenticateAccount("admin", "changed-password-long", "", key, now); e != nil {
		t.Fatal(e)
	}
	rows, e := s.DB.Query(`SELECT action,result FROM audit_logs`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b string
		rows.Scan(&a, &b)
		if strings.Contains(a+b, setup.Secret) || strings.Contains(a+b, "password-long") {
			t.Fatal("secret leaked to audit")
		}
	}
	encoded, _ := json.Marshal(out)
	if strings.Contains(string(encoded), out.Token) {
		t.Fatal("session token in JSON")
	}
}

func TestAccountExpiredSetupRescueAndRecoveryRotation(t *testing.T) {
	s, key, session, now := accountFixture(t)
	call := func(action string, sess accountSession, code string, when time.Time) (accountResult, error) {
		return s.changeAccount(action, Hash(sess.Token), sess.CSRF, accountInput{Password: "test-password-long", Code: code}, key, when)
	}
	setup, e := call("setup", session, "", now)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	expired := now.Add(11 * time.Minute)
	if _, e = call("confirm", session, hotp(raw, uint64(expired.Unix()/30), 6), expired); e == nil {
		t.Fatal("expired setup accepted")
	}
	setup, e = call("setup", session, "", expired)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	enabled, e := call("confirm", session, hotp(raw, uint64(expired.Unix()/30), 6), expired)
	if e != nil {
		t.Fatal(e)
	}
	rotated, e := call("recovery", enabled.accountSession, enabled.RecoveryCodes[0], expired)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.authenticateAccount("admin", "test-password-long", enabled.RecoveryCodes[1], key, expired); e == nil {
		t.Fatal("old recovery set survived regeneration")
	}
	if _, e = s.authenticateAccount("admin", "test-password-long", rotated.RecoveryCodes[0], key, expired); e != nil {
		t.Fatal(e)
	}
	if e = s.RecoverAccount("unknown", "local-reset-password"); e == nil {
		t.Fatal("rescue silently created account")
	}
	if e = s.RecoverAccount("admin", "local-reset-password"); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"sessions", "account_security", "account_recovery"} {
		var n int
		s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n)
		if n != 0 {
			t.Fatal("rescue retained state", table, n)
		}
	}
	if _, e = s.authenticateAccount("admin", "local-reset-password", "", key, expired); e != nil {
		t.Fatal(e)
	}
}
