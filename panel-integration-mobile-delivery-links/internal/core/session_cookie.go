package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

// Cookies are shared across host ports (RFC 6265 section 8.5). Use a stable,
// installation-specific name rather than an Origin/Host header or port. A
// domain-separated HMAC keeps the persistent credential key private and works
// unchanged through supported reverse proxies and public-origin changes.
// This prevents accidental overwrite/logout, NOT confidentiality from an
// untrusted service on another port: browsers still send host cookies to that
// service. Separate trust domains must use separate hostnames and HTTPS.
func (a *Server) sessionCookieName() string {
	mac := hmac.New(sha256.New, a.accountSecretKey)
	_, _ = mac.Write([]byte("yunzhan-session-cookie-namespace-v1"))
	return "panel_session_" + hex.EncodeToString(mac.Sum(nil)[:16])
}

func (a *Server) sessionCookie(r *http.Request) (*http.Cookie, bool, error) {
	var current, legacy []*http.Cookie
	name := a.sessionCookieName()
	for _, cookie := range r.Cookies() {
		switch cookie.Name {
		case name:
			current = append(current, cookie)
		case "panel_session":
			legacy = append(legacy, cookie)
		}
	}
	if len(current) > 1 || len(current) == 0 && len(legacy) > 1 {
		return nil, false, errors.New("ambiguous session cookie")
	}
	if len(current) == 1 {
		// An invalid or empty new cookie must never fall back to a valid old
		// cookie. Otherwise stale credentials could bypass an explicit logout.
		return current[0], false, nil
	}
	if len(legacy) == 1 {
		return legacy[0], true, nil
	}
	return nil, false, http.ErrNoCookie
}

func (a *Server) migrateSessionCookie(w http.ResponseWriter, r *http.Request, cookie *http.Cookie) {
	var expires int64
	if err := a.Store.DB.QueryRow(`SELECT expires_at FROM sessions WHERE token_hash=?`, Hash(cookie.Value)).Scan(&expires); err != nil {
		return
	}
	remaining := expires - time.Now().Unix()
	if remaining > 0 {
		a.cookie(w, r, cookie.Value, int(remaining))
	}
	// Do not clear the generic legacy cookie: another still-old panel at a
	// different port may legitimately own it. Its token still expires/revokes
	// normally; all new logins and account rotations use only the new name.
}
