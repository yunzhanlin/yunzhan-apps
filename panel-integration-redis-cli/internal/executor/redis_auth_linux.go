//go:build linux

package executor

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const redisAuthLeaf = "auth.json"

// Kept Root0600, never marshalled into instance/status/audit/command arguments.
// Redis itself receives only SHA256 ACL hashes in its read-only config.
type redisAuthSecret struct {
	Format        int    `json:"format"`
	ID            string `json:"id"`
	ReleaseID     string `json:"release_id"`
	Port          int    `json:"port"`
	CreatedAt     string `json:"created_at"`
	AdminPassword string `json:"admin_password"`
	AppPassword   string `json:"app_password"`
}

func validRedisPassword(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32
}

func (s redisAuthSecret) valid(instance core.RedisInstance) bool {
	return instance.AuthMode == core.RedisACLAuthMode && s.Format == 1 &&
		s.ID == instance.ID && s.ReleaseID == instance.ReleaseID && s.Port == instance.Port &&
		s.CreatedAt == instance.CreatedAt && validRedisPassword(s.AdminPassword) &&
		validRedisPassword(s.AppPassword) && s.AdminPassword != s.AppPassword
}

func newRedisAuthSecret(instance core.RedisInstance) (redisAuthSecret, error) {
	s := redisAuthSecret{Format: 1, ID: instance.ID, ReleaseID: instance.ReleaseID, Port: instance.Port, CreatedAt: instance.CreatedAt}
	for _, target := range []*string{&s.AdminPassword, &s.AppPassword} {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return redisAuthSecret{}, errors.New("Redis 凭据生成失败")
		}
		*target = hex.EncodeToString(raw[:])
		clear(raw[:])
	}
	if !s.valid(instance) {
		return redisAuthSecret{}, errors.New("Redis 凭据身份无效")
	}
	return s, nil
}

func redisAuthConfig(s redisAuthSecret) string {
	admin := sha256.Sum256([]byte(s.AdminPassword))
	app := sha256.Sum256([]byte(s.AppPassword))
	// https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/
	// Application credentials cannot perform administration/dangerous operations.
	// Logical DBs are NOT tenant boundaries; the app owns this complete instance.
	return fmt.Sprintf("user default reset off\nuser panel-admin reset on #%x ~* &* +@all\nuser app-%s reset on #%x ~* &* +@read +@write +@connection +@transaction +@pubsub +@scripting -@admin -@dangerous\n", admin, s.ID[:12], app)
}

func redisInstanceConfig(instance core.RedisInstance, secret redisAuthSecret) string {
	return fmt.Sprintf("bind 127.0.0.1\nprotected-mode yes\nport %d\ntcp-backlog 128\ntimeout 0\ntcp-keepalive 300\ndaemonize no\nsupervised no\npidfile /run/panel-redis-%s/redis.pid\nloglevel notice\nlogfile \"\"\ndatabases 16\nalways-show-logo no\ndir %s\ndbfilename dump.rdb\nappendonly yes\nappenddirname appendonlydir\nmaxmemory %dmb\nmaxmemory-policy allkeys-lru\nrename-command CONFIG \"\"\n", instance.Port, instance.ID, redisData(instance.ID), instance.MaxMemoryMB) + redisAuthConfig(secret)
}

func validateRedisServingAuth(instance core.RedisInstance) error {
	if err := validateRedisAuthMode(instance); err != nil {
		return err
	}
	if instance.AuthMode == "" {
		return nil
	}
	secret, err := readRedisAuth(instance)
	if err != nil {
		return err
	}
	defer func() { secret.AdminPassword = ""; secret.AppPassword = "" }()
	file := filepath.Join(redisConfig(instance.ID), "redis.conf")
	fd, err := syscall.Open(file, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("Redis 配置无法安全读取")
	}
	f := os.NewFile(uintptr(fd), file)
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0640 || before.Size() <= 0 || before.Size() > 65536 {
		return errors.New("Redis ACL 配置权限或容量无效")
	}
	meta, ok := before.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != 0 || meta.Nlink != 1 {
		return errors.New("Redis ACL 配置所有权无效")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	after, e := f.Stat()
	current, pathErr := os.Lstat(file)
	if err != nil || e != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) {
		return errors.New("Redis ACL 配置并发变化")
	}
	next, nOK := after.Sys().(*syscall.Stat_t)
	last, lOK := current.Sys().(*syscall.Stat_t)
	if !nOK || !lOK || meta.Uid != next.Uid || meta.Gid != next.Gid || meta.Mode != next.Mode || meta.Ctim != next.Ctim || next.Nlink != 1 || *next != *last {
		return errors.New("Redis ACL 配置元数据变化")
	}
	if !bytes.Equal(raw, []byte(redisInstanceConfig(instance, secret))) {
		return errors.New("Redis ACL 配置与实例凭据不一致，拒绝免密启动")
	}
	return nil
}
func writeRedisAuthSecret(dir string, s redisAuthSecret) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return errors.New("Redis 凭据序列化失败")
	}
	file, err := os.OpenFile(filepath.Join(dir, redisAuthLeaf), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("Redis 凭据文件已存在或不可安全创建")
	}
	defer file.Close()
	if err = file.Chown(0, 0); err != nil {
		return errors.New("Redis 凭据所有权设置失败")
	}
	if _, err = file.Write(append(raw, '\n')); err == nil {
		err = file.Sync()
	}
	if err != nil {
		return errors.New("Redis 凭据保存失败")
	}
	return nil
}

func decodeRedisAuth(raw []byte, instance core.RedisInstance) (redisAuthSecret, error) {
	var s redisAuthSecret
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 4096 || decoder.Decode(&s) != nil || !s.valid(instance) {
		return redisAuthSecret{}, errors.New("Redis 凭据内容或实例身份无效")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return redisAuthSecret{}, errors.New("Redis 凭据存在多余内容")
	}
	return s, nil
}

func readRedisAuthFile(file string, instance core.RedisInstance) (redisAuthSecret, error) {
	// Use O_NOFOLLOW + fstat identity, not a permission probe that Root can bypass.
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 4096 {
		return redisAuthSecret{}, errors.New("Redis 凭据文件缺失或权限无效")
	}
	inode, ok := info.Sys().(*syscall.Stat_t)
	if !ok || inode.Uid != 0 || inode.Gid != 0 || inode.Nlink != 1 {
		return redisAuthSecret{}, errors.New("Redis 凭据文件所有权无效")
	}
	fd, err := syscall.Open(file, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return redisAuthSecret{}, errors.New("Redis 凭据文件无法安全读取")
	}
	f := os.NewFile(uintptr(fd), file)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Mode() != info.Mode() || opened.Size() != info.Size() {
		return redisAuthSecret{}, errors.New("Redis 凭据文件读取身份变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	after, afterErr := f.Stat()
	pathAfter, pathErr := os.Lstat(file)
	if err != nil || afterErr != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, pathAfter) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return redisAuthSecret{}, errors.New("Redis 凭据文件并发变化")
	}
	final, ok := after.Sys().(*syscall.Stat_t)
	if !ok || final.Uid != inode.Uid || final.Gid != inode.Gid || final.Nlink != 1 || final.Mode != inode.Mode || final.Ctim != inode.Ctim {
		return redisAuthSecret{}, errors.New("Redis 凭据文件元数据变化")
	}
	last, lastOK := pathAfter.Sys().(*syscall.Stat_t)
	if !lastOK || last.Uid != final.Uid || last.Gid != final.Gid || last.Nlink != 1 || last.Mode != final.Mode || last.Ctim != final.Ctim || pathAfter.Size() != after.Size() || !pathAfter.ModTime().Equal(after.ModTime()) {
		return redisAuthSecret{}, errors.New("Redis 凭据路径并发变化")
	}
	return decodeRedisAuth(raw, instance)
}

func readRedisAuth(instance core.RedisInstance) (redisAuthSecret, error) {
	if core.ValidateRedisInstance(instance) != nil || instance.AuthMode != core.RedisACLAuthMode {
		return redisAuthSecret{}, errors.New("旧 Redis 实例未启用 ACL；不会自动改密")
	}
	dir := redisConfig(instance.ID)
	for _, name := range []string{"/etc", "/etc/panel", redisRoot, dir} {
		info, err := os.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return redisAuthSecret{}, errors.New("Redis 凭据目录不可信")
		}
		inode, ok := info.Sys().(*syscall.Stat_t)
		if !ok || inode.Uid != 0 {
			return redisAuthSecret{}, errors.New("Redis 凭据目录所有权无效")
		}
	}
	return readRedisAuthFile(filepath.Join(dir, redisAuthLeaf), instance)
}

func validateRedisAuthMode(instance core.RedisInstance) error {
	if core.ValidateRedisInstance(instance) != nil {
		return errors.New("Redis 实例身份无效")
	}
	if instance.AuthMode == core.RedisACLAuthMode {
		_, err := readRedisAuth(instance)
		return err
	}
	if instance.AuthMode != "" {
		return errors.New("Redis 认证模式无效")
	}
	// Never interpret a lost/downgraded secure manifest as permission to connect
	// without authentication. Truly old files remain byte-exact, not migrated.
	if _, err := os.Lstat(filepath.Join(redisConfig(instance.ID), redisAuthLeaf)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("Redis 认证身份冲突，拒绝免密回退")
	}
	return nil
}

func (s *Service) redisAuthRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/redis/instances/{id}/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		var empty struct{}
		if !readJSON(w, r, &empty) {
			return
		}
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		secret, err := readRedisAuth(instance)
		if err != nil {
			respond(w, 409, map[string]string{"error": "Redis 应用凭据不可用；旧实例未被修改"})
			return
		}
		out := core.RedisCredentials{Host: "127.0.0.1", Port: instance.Port, Username: "app-" + instance.ID[:12], Password: secret.AppPassword, AuthMode: core.RedisACLAuthMode}
		secret.AdminPassword = ""
		secret.AppPassword = ""
		defer func() { out.Password = "" }()
		respond(w, 200, out)
	})
}
