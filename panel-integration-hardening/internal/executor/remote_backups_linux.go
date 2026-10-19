//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func remoteHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Minute, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func verifiedRemoteBase(remote core.BackupRemote) (*url.URL, error) {
	u, e := url.Parse(remote.BaseURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("WebDAV 地址无效")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("非本机 WebDAV 必须使用 HTTPS")
		}
	}
	if len(remote.PathPrefix) > 128 || strings.Contains(remote.PathPrefix, "..") {
		return nil, errors.New("WebDAV 目录无效")
	}
	u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	return u, nil
}

func davRequest(ctx context.Context, client *http.Client, method string, target *url.URL, username, password string, body io.Reader, length int64, headers map[string]string) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, method, target.String(), body)
	if e != nil {
		return nil, e
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	if length >= 0 {
		req.ContentLength = length
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return client.Do(req)
}

func davError(response *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("WebDAV HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(b)))
}

func ensureDAVCollections(ctx context.Context, client *http.Client, base *url.URL, prefix, username, password string) error {
	segments := []string{}
	for _, segment := range strings.Split(strings.Trim(prefix, "/"), "/") {
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	for index := range segments {
		u := *base
		u.Path = path.Join(base.Path, path.Join(segments[:index+1]...)) + "/"
		response, e := davRequest(ctx, client, "MKCOL", &u, username, password, nil, 0, nil)
		if e != nil {
			return e
		}
		if response.StatusCode != 201 && response.StatusCode != 200 && response.StatusCode != 204 && response.StatusCode != 405 {
			err := davError(response)
			response.Body.Close()
			return err
		}
		response.Body.Close()
	}
	return nil
}

func openRemoteBackup(ctx context.Context, in core.RemoteBackupRequest) (*os.File, string, string, int64, string, error) {
	if !core.ValidID(in.CopyID) || (in.Kind != "database" && in.Kind != "site" && in.Kind != "mariadb") {
		return nil, "", "", 0, "", errors.New("远端复制身份无效")
	}
	if in.Kind == "database" {
		if in.Database == nil || in.Site != nil {
			return nil, "", "", 0, "", errors.New("数据库备份身份缺失")
		}
		file, actual, e := openVerifiedBackup(ctx, mysqlBackups, *in.Database)
		if e != nil {
			return nil, "", "", 0, "", e
		}
		return file, actual.DatabaseID, actual.ID + ".sql", actual.Bytes, actual.SHA256, nil
	}
	if in.Kind == "mariadb" {
		if in.MariaDB == nil || in.Database != nil || in.Site != nil {
			return nil, "", "", 0, "", errors.New("MariaDB 备份身份缺失")
		}
		actual, e := readMariaDBBackup(in.MariaDB.InstanceID, in.MariaDB.ID)
		if e != nil || actual != *in.MariaDB || verifyMariaDBBackup(actual) != nil {
			return nil, "", "", 0, "", errors.New("MariaDB 备份归属或摘要异常")
		}
		root, e := os.OpenRoot(mariaDBBackupDir(actual.InstanceID))
		if e != nil {
			return nil, "", "", 0, "", e
		}
		defer root.Close()
		file, e := root.OpenFile(actual.ID+".sql", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return nil, "", "", 0, "", e
		}
		return file, actual.DatabaseID, actual.ID + ".sql", actual.Bytes, actual.SHA256, nil
	}
	if in.Site == nil || in.Database != nil {
		return nil, "", "", 0, "", errors.New("网站备份身份缺失")
	}
	actual, e := verifySiteBackup(ctx, *in.Site)
	if e != nil {
		return nil, "", "", 0, "", e
	}
	dir := filepath.Join(siteBackups, actual.SiteID)
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, "", "", 0, "", e
	}
	defer root.Close()
	file, e := root.OpenFile(actual.ID+".zip", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, "", "", 0, "", e
	}
	info, e := file.Stat()
	if e != nil || privateBackupEntry(info, false) != nil {
		file.Close()
		return nil, "", "", 0, "", errors.New("网站备份归属或类型异常")
	}
	return file, actual.SiteID, actual.ID + ".zip", actual.Bytes, actual.SHA256, nil
}

func verifyDAVObject(ctx context.Context, client *http.Client, target *url.URL, username, password string, size int64, sha string) error {
	response, e := davRequest(ctx, client, http.MethodGet, target, username, password, nil, -1, nil)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return davError(response)
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(response.Body, size+1))
	if e != nil {
		return e
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != sha {
		return errors.New("WebDAV 远端对象大小或 SHA-256 不一致")
	}
	return nil
}

func syncRemoteBackup(ctx context.Context, in core.RemoteBackupRequest) (core.RemoteBackupResult, error) {
	var result core.RemoteBackupResult
	base, e := verifiedRemoteBase(in.Remote)
	if e != nil {
		return result, e
	}
	file, targetID, name, size, sha, e := openRemoteBackup(ctx, in)
	if e != nil {
		return result, e
	}
	defer file.Close()
	prefix := strings.Trim(in.Remote.PathPrefix, "/")
	collection := path.Join(prefix, in.Kind, targetID)
	client := remoteHTTPClient()
	defer client.CloseIdleConnections()
	if e = ensureDAVCollections(ctx, client, base, collection, in.Remote.Username, in.Password); e != nil {
		return result, e
	}
	finalURL := *base
	finalURL.Path = path.Join(base.Path, collection, name)
	tempURL := finalURL
	tempURL.Path = finalURL.Path + ".part-" + in.CopyID
	response, e := davRequest(ctx, client, http.MethodPut, &tempURL, in.Remote.Username, in.Password, file, size, map[string]string{"Content-Type": "application/octet-stream"})
	if e != nil {
		return result, e
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := davError(response)
		response.Body.Close()
		return result, err
	}
	response.Body.Close()
	if e = verifyDAVObject(ctx, client, &tempURL, in.Remote.Username, in.Password, size, sha); e != nil {
		return result, e
	}
	response, e = davRequest(ctx, client, "MOVE", &tempURL, in.Remote.Username, in.Password, nil, 0, map[string]string{"Destination": finalURL.String(), "Overwrite": "T"})
	if e != nil {
		return result, e
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := davError(response)
		response.Body.Close()
		return result, err
	}
	response.Body.Close()
	if e = verifyDAVObject(ctx, client, &finalURL, in.Remote.Username, in.Password, size, sha); e != nil {
		return result, e
	}
	manifest, _ := json.Marshal(map[string]any{"copy_id": in.CopyID, "kind": in.Kind, "artifact_id": strings.TrimSuffix(name, filepath.Ext(name)), "target_id": targetID, "bytes": size, "sha256": sha, "created_at": core.Now()})
	manifestURL := finalURL
	manifestURL.Path = finalURL.Path + ".manifest.json"
	response, e = davRequest(ctx, client, http.MethodPut, &manifestURL, in.Remote.Username, in.Password, bytes.NewReader(manifest), int64(len(manifest)), map[string]string{"Content-Type": "application/json"})
	if e != nil {
		return result, e
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := davError(response)
		response.Body.Close()
		return result, err
	}
	response.Body.Close()
	result = core.RemoteBackupResult{RemotePath: strings.TrimPrefix(finalURL.Path, base.Path), Bytes: size, SHA256: sha}
	return result, nil
}

func testRemoteConnection(ctx context.Context, in core.RemoteConnectionRequest) (core.RemoteConnectionResult, error) {
	base, e := verifiedRemoteBase(in.Remote)
	if e != nil {
		return core.RemoteConnectionResult{}, e
	}
	client := remoteHTTPClient()
	defer client.CloseIdleConnections()
	response, e := davRequest(ctx, client, "PROPFIND", base, in.Remote.Username, in.Password, strings.NewReader(`<?xml version="1.0"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>`), -1, map[string]string{"Depth": "0", "Content-Type": "application/xml"})
	if e != nil {
		return core.RemoteConnectionResult{}, e
	}
	defer response.Body.Close()
	if response.StatusCode != 207 && response.StatusCode != 200 {
		return core.RemoteConnectionResult{}, davError(response)
	}
	return core.RemoteConnectionResult{Status: "ok"}, nil
}

func (s *Service) remoteBackupRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/remote-backups/test", func(w http.ResponseWriter, r *http.Request) {
		var in core.RemoteConnectionRequest
		if !readJSON(w, r, &in) {
			return
		}
		result, e := testRemoteConnection(r.Context(), in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, result)
	})
	m.HandleFunc("POST /v1/remote-backups/sync", func(w http.ResponseWriter, r *http.Request) {
		var in core.RemoteBackupRequest
		if !readJSON(w, r, &in) {
			return
		}
		lock := fileMutex("remote-copy-" + in.CopyID)
		lock.Lock()
		defer lock.Unlock()
		result, e := syncRemoteBackup(r.Context(), in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, result)
	})
}
