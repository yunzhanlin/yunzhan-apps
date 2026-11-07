package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// HOTP uses the standardized HMAC-SHA1 construction, not SHA1 signatures.
func hotp(secret []byte, counter uint64, digits int) string {
	var input [8]byte
	binary.BigEndian.PutUint64(input[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(input[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	number := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, number%modulus)
}
func totpStep(secret []byte, code string, now time.Time, last int64) (int64, error) {
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(code) {
		return 0, errors.New("验证码无效或已使用")
	}
	step := now.Unix() / 30
	matched := int64(-1)
	for _, n := range []int64{step - 1, step, step + 1} {
		if n >= 0 && subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(n), 6)), []byte(code)) == 1 && n > last {
			matched = n
		}
	}
	if matched < 0 {
		return 0, errors.New("验证码无效或已使用")
	}
	return matched, nil
}
func newTOTPSecret() ([]byte, string, error) {
	secret := make([]byte, 20)
	if _, e := rand.Read(secret); e != nil {
		return nil, "", e
	}
	return secret, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}
func secretAEAD(key []byte) (cipher.AEAD, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func encryptAccountSecret(key []byte, user string, secret []byte) ([]byte, error) {
	return encryptCredential(key, "panel-totp:"+user, secret)
}
func encryptCredential(key []byte, purpose string, secret []byte) ([]byte, error) {
	a, e := secretAEAD(key)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, secret, []byte(purpose)), nil
}
func decryptAccountSecret(key []byte, user string, encrypted []byte) ([]byte, error) {
	return decryptCredential(key, "panel-totp:"+user, encrypted)
}
func decryptCredential(key []byte, purpose string, encrypted []byte) ([]byte, error) {
	a, e := secretAEAD(key)
	if e != nil {
		return nil, e
	}
	if len(encrypted) < a.NonceSize() {
		return nil, errors.New("验证器密钥不可读取")
	}
	return a.Open(nil, encrypted[:a.NonceSize()], encrypted[a.NonceSize():], []byte(purpose))
}
func (s *Store) accountKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "credential-key")
	info, e := os.Lstat(path)
	if e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("账户主密钥必须是权限 0600 的普通私有文件")
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		if len(data) != 32 {
			return nil, errors.New("账户主密钥长度错误")
		}
		return data, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	var n int
	if e = s.DB.QueryRow(`SELECT count(*) FROM account_security WHERE length(totp_secret)>0 OR length(pending_secret)>0`).Scan(&n); e != nil {
		return nil, e
	}
	var acmeKeys int
	if e = s.DB.QueryRow(`SELECT (SELECT count(*) FROM acme_accounts)+(SELECT count(*) FROM acme_orders)`).Scan(&acmeKeys); e != nil {
		return nil, e
	}
	if acmeKeys > 0 {
		return nil, errors.New("凭据主密钥缺失，请恢复原 credential-key 后读取 ACME 凭据")
	}
	var certificates int
	if e = s.DB.QueryRow(`SELECT count(*) FROM certificates`).Scan(&certificates); e != nil {
		return nil, e
	}
	if certificates > 0 {
		return nil, errors.New("凭据主密钥缺失，请恢复 credential-key，证书私钥不能使用替代密钥解密")
	}
	if n > 0 {
		return nil, errors.New("账户主密钥缺失，请恢复 credential-key 或使用本机救援命令")
	}
	data := make([]byte, 32)
	if _, e = rand.Read(data); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if syncErr != nil {
		return nil, syncErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	dirFile, e := os.Open(dir)
	if e != nil {
		return nil, e
	}
	dirSyncErr := dirFile.Sync()
	dirCloseErr := dirFile.Close()
	if dirSyncErr != nil {
		return nil, dirSyncErr
	}
	if dirCloseErr != nil {
		return nil, dirCloseErr
	}
	return data, nil
}
