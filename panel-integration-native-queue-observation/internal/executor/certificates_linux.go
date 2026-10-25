//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const certificateRoot = "/etc/panel/certificates"

type certificateFS struct{ root string }

func (f certificateFS) readFile(id, name string, limit int64, private bool) ([]byte, error) {
	if !core.ValidID(id) {
		return nil, errors.New("证书标识无效")
	}
	for _, dir := range []string{f.root, filepath.Join(f.root, id)} {
		if e := ownedRuntimePath(dir, true); e != nil {
			return nil, e
		}
		info, e := os.Stat(dir)
		if e != nil || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("证书目录权限应为 0700")
		}
	}
	path := filepath.Join(f.root, id, name)
	if e := ownedRuntimePath(path, false); e != nil {
		return nil, e
	}
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if private && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("证书私钥或元数据权限应为 0600")
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	b, e := io.ReadAll(io.LimitReader(file, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("证书文件超出大小限制")
	}
	return b, nil
}
func (f certificateFS) load(id string) (core.Certificate, error) {
	var saved core.Certificate
	b, e := f.readFile(id, "manifest.json", 16384, true)
	if e != nil {
		return saved, e
	}
	if e = json.Unmarshal(b, &saved); e != nil {
		return saved, e
	}
	if saved.ID != id {
		return saved, errors.New("证书清单归属不匹配")
	}
	chain, e := f.readFile(id, "chain.pem", 32768, false)
	if e != nil {
		return saved, e
	}
	key, e := f.readFile(id, "key.pem", 16384, true)
	if e != nil {
		return saved, e
	}
	actual, e := core.ParseCertificate(string(chain), string(key), time.Now())
	if e != nil {
		return saved, e
	}
	if actual.Fingerprint != saved.Fingerprint || actual.ChainSHA != saved.ChainSHA {
		return saved, errors.New("证书文件摘要与清单不匹配")
	}
	actual.ID = id
	actual.CreatedAt = saved.CreatedAt
	return actual, nil
}
func (f certificateFS) install(in core.CertificateMaterial) (core.Certificate, error) {
	var empty core.Certificate
	if !core.ValidID(in.ID) {
		return empty, errors.New("证书标识无效")
	}
	cert, e := core.ParseCertificate(in.CertificatePEM, in.PrivateKeyPEM, time.Now())
	if e != nil {
		return empty, e
	}
	cert.ID = in.ID
	cert.CreatedAt = core.Now()
	if e = os.MkdirAll(f.root, 0700); e != nil {
		return empty, e
	}
	if e = ownedRuntimePath(f.root, true); e != nil {
		return empty, e
	}
	info, e := os.Stat(f.root)
	if e != nil {
		return empty, e
	}
	if info.Mode().Perm()&0077 != 0 {
		return empty, errors.New("证书目录权限应为 0700")
	}
	target := filepath.Join(f.root, in.ID)
	if _, e = os.Lstat(target); e == nil {
		old, e := f.load(in.ID)
		if e != nil {
			return empty, e
		}
		if old.Fingerprint != cert.Fingerprint || old.ChainSHA != cert.ChainSHA {
			return empty, errors.New("证书 ID 已对应其他内容，拒绝覆盖")
		}
		return old, nil
	} else if !os.IsNotExist(e) {
		return empty, e
	}
	stage, e := os.MkdirTemp(f.root, ".pending-"+in.ID+"-")
	if e != nil {
		return empty, e
	}
	defer os.RemoveAll(stage)
	if e = atomicWrite(filepath.Join(stage, "chain.pem"), []byte(cert.PEM), 0644); e != nil {
		return empty, e
	}
	if e = atomicWrite(filepath.Join(stage, "key.pem"), []byte(in.PrivateKeyPEM), 0600); e != nil {
		return empty, e
	}
	b, e := json.Marshal(cert)
	if e != nil {
		return empty, e
	}
	if e = atomicWrite(filepath.Join(stage, "manifest.json"), b, 0600); e != nil {
		return empty, e
	}
	root, e := os.OpenRoot(f.root)
	if e != nil {
		return empty, e
	}
	defer root.Close()
	if e = renameNoReplace(root, filepath.Base(stage), in.ID); e != nil {
		return empty, e
	}
	if e = syncRuntimeDirs(f.root); e != nil {
		return empty, e
	}
	return f.load(in.ID)
}
func LoadCertificate(id string) (core.Certificate, error) {
	return (certificateFS{root: certificateRoot}).load(id)
}
func (s *Service) certificateRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/certificates/install", func(w http.ResponseWriter, r *http.Request) {
		var in core.CertificateMaterial
		if !readJSON(w, r, &in) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		cert, e := (certificateFS{root: certificateRoot}).install(in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, cert)
	})
}
