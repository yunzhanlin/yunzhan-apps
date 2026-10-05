package core

import (
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// Serve precompressed, content-hashed frontend assets so the first visit to a
// remote panel does not transfer the full uncompressed JavaScript bundle.
func panelStaticHandler(root string) http.Handler {
	plain := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		ext := path.Ext(clean)
		if !strings.HasPrefix(clean, "/assets/") || (ext != ".js" && ext != ".css") {
			// Never let heuristic browser caching pin index.html (and therefore an
			// obsolete manager/router) after the signed release is upgraded. Only
			// content-hashed build assets get the long immutable cache policy.
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			plain.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		if !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			plain.ServeHTTP(w, r)
			return
		}
		compressed := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(clean, "/"))) + ".gz"
		file, err := os.Open(compressed)
		if err != nil {
			plain.ServeHTTP(w, r)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			plain.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", mime.TypeByExtension(ext))
		w.Header().Set("Content-Encoding", "gzip")
		http.ServeContent(w, r, path.Base(clean)+".gz", info.ModTime(), file)
	})
}

func acceptsGzip(header string) bool {
	for _, encoding := range strings.Split(header, ",") {
		parts := strings.Split(strings.TrimSpace(encoding), ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
			continue
		}
		for _, parameter := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "q") {
				quality, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				return err == nil && quality > 0
			}
		}
		return true
	}
	return false
}
