//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"path"
	"strings"
	"time"
)

// Cloud uploads reuse the administrator's encrypted WebDAV account, but take
// the source only from a site's confined public directory.
func (s *Service) uploadSiteFileToDAV(ctx context.Context, siteID string, in core.FileCloudUpload) (core.FileCloudUploadResult, error) {
	var out core.FileCloudUploadResult
	if !core.ValidID(siteID) || !core.ValidFilePath(in.Path, false) || !in.Remote.Enabled {
		return out, errors.New("站点文件或 WebDAV 远端无效")
	}
	base, e := verifiedRemoteBase(in.Remote)
	if e != nil {
		return out, e
	}
	f, e := s.openFiles(siteID)
	if e != nil {
		return out, e
	}
	defer f.Close()
	file, e := regularFile(f.public, in.Path)
	if e != nil {
		return out, e
	}
	defer file.Close()
	st, e := file.Stat()
	if e != nil || st.Size() < 0 || st.Size() > core.MaxFileUpload {
		return out, errors.New("只允许上传不超过 512 MiB 的普通文件")
	}
	collection := path.Join(strings.Trim(in.Remote.PathPrefix, "/"), "files", siteID, path.Dir(in.Path))
	client := remoteHTTPClient()
	defer client.CloseIdleConnections()
	if e = ensureDAVCollections(ctx, client, base, collection, in.Remote.Username, in.Password); e != nil {
		return out, e
	}
	finalURL := *base
	finalURL.Path = path.Join(base.Path, collection, path.Base(in.Path))
	tempURL := finalURL
	tempURL.Path += ".part-" + core.ID()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, er := http.NewRequestWithContext(cleanupCtx, http.MethodDelete, tempURL.String(), nil)
		if er != nil {
			return
		}
		req.SetBasicAuth(in.Remote.Username, in.Password)
		if response, er := client.Do(req); er == nil {
			response.Body.Close()
		}
	}()
	h := sha256.New()
	response, e := davRequest(ctx, client, http.MethodPut, &tempURL, in.Remote.Username, in.Password, io.TeeReader(file, h), st.Size(), map[string]string{"Content-Type": "application/octet-stream"})
	if e != nil {
		return out, e
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := davError(response)
		response.Body.Close()
		return out, err
	}
	response.Body.Close()
	sha := hex.EncodeToString(h.Sum(nil))
	if e = verifyDAVObject(ctx, client, &tempURL, in.Remote.Username, in.Password, st.Size(), sha); e != nil {
		return out, e
	}
	response, e = davRequest(ctx, client, "MOVE", &tempURL, in.Remote.Username, in.Password, nil, 0, map[string]string{"Destination": finalURL.String(), "Overwrite": "F"})
	if e != nil {
		return out, e
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := davError(response)
		response.Body.Close()
		return out, err
	}
	response.Body.Close()
	if e = verifyDAVObject(ctx, client, &finalURL, in.Remote.Username, in.Password, st.Size(), sha); e != nil {
		return out, e
	}
	return core.FileCloudUploadResult{RemotePath: finalURL.String(), Bytes: st.Size(), SHA256: sha}, nil
}

func (s *Service) fileCloudRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/{id}/files/cloud-upload", func(w http.ResponseWriter, r *http.Request) {
		var in core.FileCloudUpload
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF {
			respond(w, 400, map[string]string{"error": "云存储参数无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
		defer cancel()
		out, e := s.uploadSiteFileToDAV(ctx, r.PathValue("id"), in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, out)
	})
}
