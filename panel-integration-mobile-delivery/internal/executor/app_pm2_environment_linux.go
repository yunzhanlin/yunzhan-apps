//go:build linux

package executor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

var pm2EnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func validPM2Environment(values map[string]string) error {
	if len(values) > 64 {
		return errors.New("环境变量最多 64 项")
	}
	total := 0
	for key, value := range values {
		upper := strings.ToUpper(key)
		if !pm2EnvironmentName.MatchString(key) || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") || strings.HasPrefix(upper, "PM2_") || strings.HasPrefix(upper, "NPM_") || strings.HasPrefix(upper, "NODE_") && upper != "NODE_ENV" {
			return errors.New("环境变量名称无效或属于运行器保留字段")
		}
		switch upper {
		case "PATH", "HOME", "HOST", "PORT", "LANG", "SHELL", "PWD", "USER", "LOGNAME", "ENV", "BASH_ENV", "IFS", "TMPDIR":
			return errors.New("不能覆盖运行器身份、监听或加载配置")
		}
		if strings.ContainsRune(value, 0) || len(value) > 8192 {
			return errors.New("变量值不能含 NUL，单项最多 8 KiB")
		}
		total += len(key) + len(value)
	}
	if total > 16384 {
		return errors.New("环境变量总大小最多 16 KiB")
	}
	return nil
}

// This key is separate from integrity-signing keys. An existing damaged or
// missing key never silently resets ciphertext or turns it into plaintext.
func (s *Service) pm2EnvironmentKey(create bool) ([]byte, error) {
	path := filepath.Join(s.moduleDir("pm2-manager"), "environment.key")
	if err := ordinary(path, false); err == nil {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		key, err := io.ReadAll(io.LimitReader(f, 33))
		if err != nil {
			return nil, err
		}
		if len(key) != 32 || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("环境变量密钥损坏或权限不安全")
		}
		return key, nil
	} else if !os.IsNotExist(err) || !create {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	return key, closeErr
}

func pm2EnvironmentPurpose(app pm2App) []byte {
	return []byte("yunzhan-pm2-env-v1:" + app.ID + ":" + app.SiteID)
}

func (s *Service) readPM2Environment(app pm2App) (map[string]string, error) {
	values := map[string]string{}
	if app.EnvironmentCipher == "" {
		return values, nil
	}
	key, err := s.pm2EnvironmentKey(false)
	if err != nil {
		return nil, errors.New("不能读取现有环境变量密钥，配置未重置")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(app.EnvironmentCipher)
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("环境变量密文无效")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], pm2EnvironmentPurpose(app))
	if err != nil || json.Unmarshal(plain, &values) != nil {
		return nil, errors.New("环境变量认证失败，拒绝启动或覆盖")
	}
	return values, validPM2Environment(values)
}

func (s *Service) patchPM2Environment(app *pm2App, patch map[string]*string) error {
	values, err := s.readPM2Environment(*app)
	if err != nil {
		return err
	}
	if len(patch) > 64 {
		return errors.New("一次最多修改 64 项环境变量")
	}
	for key, value := range patch {
		// Validate names even when deleting; deletion cannot smuggle a reserved
		// field through the API and does not acknowledge an unsafe setting.
		if err = validPM2Environment(map[string]string{key: ""}); err != nil {
			return err
		}
		if value == nil {
			delete(values, key)
		} else {
			values[key] = *value
		}
	}
	if err = validPM2Environment(values); err != nil {
		return err
	}
	app.EnvironmentKeys = nil
	for key := range values {
		app.EnvironmentKeys = append(app.EnvironmentKeys, key)
	}
	sort.Strings(app.EnvironmentKeys)
	if len(values) == 0 {
		app.EnvironmentCipher = ""
		return nil
	}
	if patch == nil {
		return nil
	}
	key, err := s.pm2EnvironmentKey(true)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	app.EnvironmentCipher = base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, raw, pm2EnvironmentPurpose(*app)))
	return nil
}

func publicPM2App(app pm2App) pm2App { app.EnvironmentCipher = ""; return app }

func pm2Environment(binary, home string, port int, values map[string]string) []string {
	env := []string{"PATH=" + filepath.Dir(binary) + ":/usr/bin:/bin", "LANG=C", "HOME=" + home, "PM2_HOME=" + home, "HOST=127.0.0.1", "PORT=" + strconv.Itoa(port)}
	if _, exists := values["NODE_ENV"]; !exists {
		env = append(env, "NODE_ENV=production")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}
