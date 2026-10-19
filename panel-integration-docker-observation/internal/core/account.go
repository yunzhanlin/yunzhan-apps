package core

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var errCredentials = errors.New("用户名、密码或验证码不正确")
var errAccountProof = errors.New("当前密码或验证码不正确")

type accountSession struct {
	Username string `json:"username"`
	CSRF     string `json:"csrf"`
	Token    string `json:"-"`
}
type accountInput struct {
	Password    string `json:"password"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
	Email       string `json:"email"`
}
type accountResult struct {
	accountSession
	Secret        string   `json:"secret,omitempty"`
	URI           string   `json:"uri,omitempty"`
	ExpiresAt     int64    `json:"expires_at,omitempty"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}
type accountProof struct {
	ID, Username string
	Password     []byte
	Secret       []byte
	LastStep     int64
}

func (s *Store) migrateAccountSecurity() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=7`).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return nil
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`CREATE TABLE account_security(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,totp_secret BLOB NOT NULL DEFAULT X'',last_step INTEGER NOT NULL DEFAULT -1,pending_secret BLOB NOT NULL DEFAULT X'',pending_expires INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE account_recovery(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,code_hash TEXT NOT NULL,used_at INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(user_id,code_hash));
 INSERT INTO schema_migrations VALUES(7,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) migrateAccountProfile() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=33`).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return nil
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`CREATE TABLE account_profiles(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,email TEXT NOT NULL DEFAULT ''); INSERT INTO schema_migrations VALUES(33,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`); e != nil {
		return e
	}
	return tx.Commit()
}
func accountByName(tx *sql.Tx, name string) (accountProof, error) {
	var a accountProof
	e := tx.QueryRow(`SELECT u.id,u.username,u.password_hash,COALESCE(s.totp_secret,X''),COALESCE(s.last_step,-1) FROM users u LEFT JOIN account_security s ON s.user_id=u.id WHERE u.username=?`, name).Scan(&a.ID, &a.Username, &a.Password, &a.Secret, &a.LastStep)
	return a, e
}
func accountAudit(tx *sql.Tx, actor, action, result string) error {
	_, e := tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,'account',?,?)`, actor, action, result, Now())
	return e
}
func checkPassword(a accountProof, password string) bool {
	hash := a.Password
	if len(hash) == 0 {
		hash = []byte("$2a$12$5pt/Ml6BaUBMFvdIOHZAB.zhdVSxyKBcIQSZ9rrLKfzRgFO/eEQC6")
	}
	e := bcrypt.CompareHashAndPassword(hash, []byte(password))
	return e == nil && a.ID != ""
}

// VerifyAccountProof performs a fresh password and second-factor check for
// privileged features without extending or replacing the browser login.
func (s *Store) VerifyAccountProof(username, password, code string, key []byte, now time.Time) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := accountByName(tx, username)
	if e != nil || !checkPassword(a, password) {
		return errAccountProof
	}
	if e = consumeAccountFactor(tx, a, key, code, now); e != nil {
		return errAccountProof
	}
	return tx.Commit()
}
func consumeAccountFactor(tx *sql.Tx, a accountProof, key []byte, code string, now time.Time) error {
	if len(a.Secret) == 0 {
		return nil
	}
	secret, e := decryptAccountSecret(key, a.ID, a.Secret)
	if e != nil {
		return errAccountProof
	}
	code = strings.TrimSpace(code)
	if step, e := totpStep(secret, code, now, a.LastStep); e == nil {
		_, e = tx.Exec(`UPDATE account_security SET last_step=? WHERE user_id=?`, step, a.ID)
		return e
	}
	normalized := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(normalized) {
		return errAccountProof
	}
	result, e := tx.Exec(`UPDATE account_recovery SET used_at=? WHERE user_id=? AND code_hash=? AND used_at=0`, now.Unix(), a.ID, Hash("recovery:"+a.ID+":"+normalized))
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errAccountProof
	}
	return nil
}
func issueAccountSession(tx *sql.Tx, a accountProof, now time.Time, rotate bool) (accountSession, error) {
	var e error
	if rotate {
		_, e = tx.Exec(`DELETE FROM sessions WHERE user_id=?`, a.ID)
		if e != nil {
			return accountSession{}, e
		}
	}
	if _, e = tx.Exec(`DELETE FROM sessions WHERE expires_at<=?`, now.Unix()); e != nil {
		return accountSession{}, e
	}
	session := accountSession{Username: a.Username, Token: Token(), CSRF: Token()}
	_, e = tx.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)`, Hash(session.Token), a.ID, session.CSRF, now.Add(12*time.Hour).Unix(), now.Unix())
	return session, e
}
func (s *Store) authenticateAccount(username, password, code string, key []byte, now time.Time) (accountSession, error) {
	tx, e := s.DB.Begin()
	if e != nil {
		return accountSession{}, e
	}
	defer tx.Rollback()
	a, e := accountByName(tx, username)
	valid := checkPassword(a, password)
	if e != nil || !valid {
		return accountSession{}, errCredentials
	}
	if e = consumeAccountFactor(tx, a, key, code, now); e != nil {
		return accountSession{}, errCredentials
	}
	result, e := issueAccountSession(tx, a, now, false)
	if e != nil {
		return result, e
	}
	if e = accountAudit(tx, a.Username, "auth.login", "success"); e != nil {
		return result, e
	}
	return result, tx.Commit()
}
func newRecoveryCodes(tx *sql.Tx, id string) ([]string, error) {
	if _, e := tx.Exec(`DELETE FROM account_recovery WHERE user_id=?`, id); e != nil {
		return nil, e
	}
	out := []string{}
	for range 10 {
		raw := ID()
		if _, e := tx.Exec(`INSERT INTO account_recovery(user_id,code_hash) VALUES(?,?)`, id, Hash("recovery:"+id+":"+raw)); e != nil {
			return nil, e
		}
		out = append(out, raw[:8]+"-"+raw[8:16]+"-"+raw[16:24]+"-"+raw[24:])
	}
	return out, nil
}
func (s *Store) changeAccount(action, sessionHash, csrf string, in accountInput, key []byte, now time.Time) (accountResult, error) {
	var result accountResult
	if action == "password" && (len(in.NewPassword) < 12 || len(in.NewPassword) > 72) || action == "profile" && in.NewPassword != "" && (len(in.NewPassword) < 12 || len(in.NewPassword) > 72) {
		return result, errors.New("新密码需为 12–72 字节")
	}
	if action == "profile" {
		in.Email = strings.TrimSpace(in.Email)
		if len(in.Email) > 254 {
			return result, errors.New("邮箱地址过长")
		}
		if in.Email != "" {
			address, e := mail.ParseAddress(in.Email)
			if e != nil || address.Address != in.Email || strings.ContainsAny(in.Email, "\r\n\t ") {
				return result, errors.New("邮箱地址格式无效")
			}
		}
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	var username, storedCSRF string
	if e = tx.QueryRow(`SELECT u.username,s.csrf FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?`, sessionHash, now.Unix()).Scan(&username, &storedCSRF); e != nil || subtle.ConstantTimeCompare([]byte(csrf), []byte(storedCSRF)) != 1 {
		return result, errors.New("当前会话已失效，请重新登录")
	}
	a, e := accountByName(tx, username)
	if e != nil || !checkPassword(a, in.Password) {
		return result, errAccountProof
	}
	if _, e = tx.Exec(`INSERT OR IGNORE INTO account_security(user_id) VALUES(?)`, a.ID); e != nil {
		return result, e
	}
	if action == "setup" || action == "confirm" {
		if len(a.Secret) > 0 {
			return result, errors.New("双重验证已经开启，请先核对当前状态")
		}
	} else if e = consumeAccountFactor(tx, a, key, in.Code, now); e != nil {
		return result, errAccountProof
	}
	switch action {
	case "setup":
		raw, text, e := newTOTPSecret()
		if e != nil {
			return result, e
		}
		encrypted, e := encryptAccountSecret(key, a.ID, raw)
		if e != nil {
			return result, e
		}
		expires := now.Add(10 * time.Minute).Unix()
		if _, e = tx.Exec(`UPDATE account_security SET pending_secret=?,pending_expires=? WHERE user_id=?`, encrypted, expires, a.ID); e != nil {
			return result, e
		}
		params := url.Values{"secret": {text}, "issuer": {"自有面板"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
		result.Secret = text
		result.URI = "otpauth://totp/" + url.PathEscape("自有面板:"+a.Username) + "?" + params.Encode()
		result.ExpiresAt = expires
	case "confirm":
		var pending []byte
		var expires int64
		if e = tx.QueryRow(`SELECT pending_secret,pending_expires FROM account_security WHERE user_id=?`, a.ID).Scan(&pending, &expires); e != nil {
			return result, e
		}
		if len(pending) == 0 || expires <= now.Unix() {
			return result, errors.New("设置密钥已过期，请重新开始")
		}
		raw, e := decryptAccountSecret(key, a.ID, pending)
		if e != nil {
			return result, errors.New("设置密钥不可读取")
		}
		step, e := totpStep(raw, in.Code, now, -1)
		if e != nil {
			return result, e
		}
		if _, e = tx.Exec(`UPDATE account_security SET totp_secret=pending_secret,last_step=?,pending_secret=X'',pending_expires=0 WHERE user_id=?`, step, a.ID); e != nil {
			return result, e
		}
		result.RecoveryCodes, e = newRecoveryCodes(tx, a.ID)
		if e != nil {
			return result, e
		}
	case "disable":
		if len(a.Secret) == 0 {
			return result, errors.New("双重验证尚未开启")
		}
		if _, e = tx.Exec(`DELETE FROM account_security WHERE user_id=?`, a.ID); e != nil {
			return result, e
		}
		if _, e = tx.Exec(`DELETE FROM account_recovery WHERE user_id=?`, a.ID); e != nil {
			return result, e
		}
	case "recovery":
		if len(a.Secret) == 0 {
			return result, errors.New("请先开启双重验证")
		}
		result.RecoveryCodes, e = newRecoveryCodes(tx, a.ID)
		if e != nil {
			return result, e
		}
	case "password":
		hash, e := bcrypt.GenerateFromPassword([]byte(in.NewPassword), 12)
		if e != nil {
			return result, e
		}
		if _, e = tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, a.ID); e != nil {
			return result, e
		}
	case "profile":
		if _, e = tx.Exec(`INSERT INTO account_profiles(user_id,email) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET email=excluded.email`, a.ID, in.Email); e != nil {
			return result, e
		}
		if in.NewPassword != "" {
			hash, er := bcrypt.GenerateFromPassword([]byte(in.NewPassword), 12)
			if er != nil {
				return result, er
			}
			if _, e = tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, a.ID); e != nil {
				return result, e
			}
		}
	default:
		return result, errors.New("不支持的账户操作")
	}
	if action != "setup" {
		result.accountSession, e = issueAccountSession(tx, a, now, true)
		if e != nil {
			return result, e
		}
	}
	if e = accountAudit(tx, a.Username, "account."+action, "success"); e != nil {
		return result, e
	}
	return result, tx.Commit()
}
func (a *Server) accountRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/account", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var enabled, count int
		var email string
		if e := a.Store.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM account_security WHERE user_id=? AND length(totp_secret)>0),(SELECT count(*) FROM account_recovery WHERE user_id=? AND used_at=0),COALESCE((SELECT email FROM account_profiles WHERE user_id=?),'')`, u.ID, u.ID, u.ID).Scan(&enabled, &count, &email); e != nil {
			fail(w, 500, "账户状态不可读取")
			return
		}
		send(w, 200, map[string]any{"username": u.Username, "email": email, "totp_enabled": enabled == 1, "recovery_remaining": count, "server_time": time.Now().UTC().Format(time.RFC3339)})
	}))
	m.HandleFunc("POST /api/account/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !a.allowedScope(r, "account:"+u.ID) {
			fail(w, 429, "账户验证过于频繁，请稍后再试")
			return
		}
		var in accountInput
		if !decode(w, r, &in) {
			return
		}
		cookie, _, _ := a.sessionCookie(r)
		out, e := a.Store.changeAccount(r.PathValue("action"), Hash(cookie.Value), u.CSRF, in, a.accountSecretKey, time.Now())
		if e != nil {
			_ = a.Store.Audit(u.Username, "account.change", "account", "denied")
			fail(w, 400, e.Error())
			return
		}
		if out.Token != "" {
			a.cookie(w, r, out.Token, 43200)
		}
		send(w, 200, out)
	}))
}
