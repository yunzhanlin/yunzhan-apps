package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOutboundSlowReceiverCanBePausedWithoutBlockingOtherChannels(t *testing.T) {
	s := testStore(t)
	master := accessUser(t, s, "master", "", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		method := "PUT"
		if path == "/api/login" {
			method = "POST"
		}
		r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := request("/api/login", map[string]string{"username": master.Username, "password": "access-test-password-long"}, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	var session accountSession
	if err = json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	entered, cancelled := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-release:
		}
	}))
	defer slow.Close()
	defer close(release)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer fast.Close()
	c := outboundCreate(t, s, slow.URL)
	other := outboundCreate(t, s, fast.URL)
	outboundEvent(t, s, "sync")
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- a.dispatchOutbound(ctx, webhookHTTPClient()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("receiver never received actual request")
	}
	// A stale revision cannot cancel a legitimate in-flight request.
	in := NotificationChannelInput{Name: c.Name, Kinds: c.Kinds, Revision: c.Revision + 1, Enabled: false}
	w := request("/api/notification-channels/"+c.ID, in, cookie, session.CSRF)
	if w.Code != 409 {
		t.Fatal("stale revision accepted", w.Code, w.Body.String())
	}
	select {
	case <-cancelled:
		t.Fatal("rejected revision cancelled legitimate request")
	default:
	}
	in.Revision = c.Revision
	started := time.Now()
	w = request("/api/notification-channels/"+c.ID, in, cookie, session.CSRF)
	if w.Code != 200 || time.Since(started) > 2*time.Second {
		t.Fatal("pause was blocked by receiver", w.Code, w.Body.String(), time.Since(started))
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("active HTTP request was not interrupted")
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unrelated channel was blocked")
	}
	h, err := s.NotificationDeliveryHistory(c.ID)
	if err != nil || len(h) != 1 || h[0]["state"] != "cancelled" {
		t.Fatal("late completion overwrote paused state", h, err)
	}
	h, err = s.NotificationDeliveryHistory(other.ID)
	if err != nil || len(h) != 1 || h[0]["state"] != "succeeded" {
		t.Fatal("unrelated channel did not deliver", h, err)
	}
	a.outboundMu.Lock()
	remaining := len(a.outboundCancels)
	a.outboundMu.Unlock()
	if remaining != 0 {
		t.Fatal("request cancellation handle leaked")
	}
}
