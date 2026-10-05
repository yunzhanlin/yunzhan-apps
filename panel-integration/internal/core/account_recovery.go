package core

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

// RecoverAccount is used by the local privileged recovery command, never an HTTP route.
func (s *Store) RecoverAccount(username, password string) error {
	if len(password) < 12 || len(password) > 72 {
		return errors.New("新密码需为 12–72 字节")
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), 12)
	if e != nil {
		return e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := accountByName(tx, username)
	if e != nil {
		return errors.New("指定管理员不存在")
	}
	for _, q := range []string{`DELETE FROM sessions WHERE user_id=?`, `DELETE FROM account_security WHERE user_id=?`, `DELETE FROM account_recovery WHERE user_id=?`} {
		if _, e = tx.Exec(q, a.ID); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, a.ID); e != nil {
		return e
	}
	if e = accountAudit(tx, "local-root", "account.rescue:"+a.Username, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
