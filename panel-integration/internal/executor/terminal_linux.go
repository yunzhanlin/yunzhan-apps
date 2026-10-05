//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"local/panel/internal/core"
)

const (
	terminalOutputLimit = 1024 * 1024
	terminalChunkLimit  = 256 * 1024
	terminalIdleTimeout = 15 * time.Minute
	terminalExitKeep    = 2 * time.Minute
	terminalMaxSessions = 4
)

type terminalManager struct {
	mu       sync.Mutex
	sessions map[string]*terminalSession
	creating int
	account  string
	workDir  string
	max      int
	idle     time.Duration
}

type terminalSession struct {
	mu         sync.Mutex
	id         string
	pty        *os.File
	cmd        *exec.Cmd
	output     []byte
	base       uint64
	running    bool
	exitCode   int
	startedAt  time.Time
	lastActive time.Time
	exitedAt   time.Time
	closed     bool
	user       string
}

type terminalCreateRequest struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

type terminalInputRequest struct {
	Data string `json:"data"`
}

type terminalResizeRequest struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

type terminalSnapshot struct {
	ID        string `json:"id"`
	Output    string `json:"output"`
	Base      uint64 `json:"base"`
	Next      uint64 `json:"next"`
	Truncated bool   `json:"truncated"`
	Running   bool   `json:"running"`
	ExitCode  int    `json:"exit_code"`
	StartedAt string `json:"started_at"`
	IdleSecs  int64  `json:"idle_seconds"`
	User      string `json:"user"`
}

func newTerminalManager(account string) *terminalManager {
	m := &terminalManager{sessions: map[string]*terminalSession{}, account: account, max: terminalMaxSessions, idle: terminalIdleTimeout, workDir: "/var/lib/panel-tasks/work"}
	if account == "root" {
		m.max = 1
		m.idle = 5 * time.Minute
		m.workDir = "/root"
	}
	go m.reap()
	return m
}

func terminalSize(cols, rows uint16) *pty.Winsize {
	if cols < 40 || cols > 400 {
		cols = 100
	}
	if rows < 10 || rows > 200 {
		rows = 32
	}
	return &pty.Winsize{Cols: cols, Rows: rows}
}

func (m *terminalManager) create(in terminalCreateRequest) (*terminalSession, error) {
	m.mu.Lock()
	active := 0
	for _, session := range m.sessions {
		session.mu.Lock()
		if session.running {
			active++
		}
		session.mu.Unlock()
	}
	if active+m.creating >= m.max {
		m.mu.Unlock()
		return nil, errors.New("受限终端会话已达到上限")
	}
	m.creating++
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.creating--
		m.mu.Unlock()
	}()

	account, err := user.Lookup(m.account)
	if err != nil {
		return nil, errors.New("受限终端账户不存在")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, errors.New("受限终端账户 UID 无效")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, errors.New("受限终端账户 GID 无效")
	}
	if os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return nil, errors.New("终端会话服务必须以 panel-task 独立身份运行")
	}
	work := m.workDir
	if err = ordinary(work, true); err != nil {
		return nil, errors.New("受限终端工作目录不可用")
	}
	if err = ordinary("/bin/bash", false); err != nil {
		return nil, errors.New("受限终端 shell 不可用")
	}
	cmd := exec.Command("/bin/bash", "--noprofile", "--norc")
	cmd.Dir = work
	cmd.Env = []string{
		"HOME=" + work,
		"USER=" + m.account,
		"LOGNAME=" + m.account,
		"SHELL=/bin/bash",
		"TERM=xterm-256color",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"HISTFILE=/dev/null",
		"PS1=\\[\\033[01;32m\\][" + m.account + "@\\h \\W]\\$ \\[\\033[00m\\]",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGHUP}
	ptmx, err := pty.StartWithSize(cmd, terminalSize(in.Cols, in.Rows))
	if err != nil {
		return nil, err
	}
	_ = syscall.SetNonblock(int(ptmx.Fd()), true)
	now := time.Now()
	session := &terminalSession{id: core.ID(), pty: ptmx, cmd: cmd, running: true, exitCode: -1, startedAt: now, lastActive: now, user: m.account}
	m.mu.Lock()
	m.sessions[session.id] = session
	m.mu.Unlock()
	go session.capture()
	go session.wait()
	return session, nil
}

func (s *terminalSession) appendOutput(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.output = append(s.output, data...)
	if extra := len(s.output) - terminalOutputLimit; extra > 0 {
		s.output = append([]byte(nil), s.output[extra:]...)
		s.base += uint64(extra)
	}
}

func (s *terminalSession) capture() {
	defer s.pty.Close()
	buf := make([]byte, 32*1024)
	for {
		n, err := s.pty.Read(buf)
		if n > 0 {
			s.appendOutput(buf[:n])
		}
		if err == nil {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EIO) {
			return
		}
		return
	}
}

func (s *terminalSession) wait() {
	err := s.cmd.Wait()
	code := 0
	if err != nil {
		code = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
	}
	s.mu.Lock()
	s.running = false
	s.exitCode = code
	s.exitedAt = time.Now()
	s.mu.Unlock()
}

func (m *terminalManager) get(id string) (*terminalSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (s *terminalSession) snapshot(after uint64) terminalSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	idle := time.Since(s.lastActive)
	s.lastActive = time.Now()
	totalNext := s.base + uint64(len(s.output))
	truncated := after < s.base
	if after < s.base {
		after = s.base
	}
	if after > totalNext {
		after = totalNext
	}
	end := after + terminalChunkLimit
	if end > totalNext {
		end = totalNext
	}
	chunk := append([]byte(nil), s.output[after-s.base:end-s.base]...)
	return terminalSnapshot{
		ID: s.id, Output: base64.StdEncoding.EncodeToString(chunk), Base: s.base, Next: end,
		Truncated: truncated, Running: s.running || end < totalNext, ExitCode: s.exitCode,
		StartedAt: s.startedAt.UTC().Format(time.RFC3339), IdleSecs: int64(idle.Seconds()), User: s.user,
	}
}

func (s *terminalSession) write(data []byte) error {
	if len(data) == 0 || len(data) > 8192 {
		return errors.New("终端输入长度必须为 1–8192 字节")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.closed {
		return errors.New("终端会话已经结束")
	}
	s.lastActive = time.Now()
	_, err := s.pty.Write(data)
	return err
}

func (s *terminalSession) resize(cols, rows uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.closed {
		return errors.New("终端会话已经结束")
	}
	s.lastActive = time.Now()
	return pty.Setsize(s.pty, terminalSize(cols, rows))
}

func (s *terminalSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	running := s.running
	pid := 0
	if s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}
	s.mu.Unlock()
	if running && pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGHUP)
	}
	_ = s.pty.Close()
}

func (m *terminalManager) remove(id string) bool {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if ok {
		s.close()
	}
	return ok
}

func (m *terminalManager) reap() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for id, session := range m.sessions {
			session.mu.Lock()
			idle := now.Sub(session.lastActive)
			running := session.running
			exitedAt := session.exitedAt
			session.mu.Unlock()
			if (running && idle >= m.idle) || (!running && !exitedAt.IsZero() && now.Sub(exitedAt) >= terminalExitKeep) {
				delete(m.sessions, id)
				go session.close()
			}
		}
		m.mu.Unlock()
	}
}

func (s *Service) terminalRoutes(m *http.ServeMux) {
	if s.Config.TerminalSocket != "" {
		registerTerminalProxy(m, "/v1/terminal", s.Config.TerminalSocket)
		if s.Config.RootTerminalSocket != "" {
			registerTerminalProxy(m, "/v1/terminal/root", s.Config.RootTerminalSocket)
		}
		return
	}
	registerTerminalHandler(m, s.terminal)
}

func registerTerminalHandler(m *http.ServeMux, manager *terminalManager) {
	m.HandleFunc("POST /v1/terminal/sessions", func(w http.ResponseWriter, r *http.Request) {
		var in terminalCreateRequest
		if !readJSON(w, r, &in) {
			return
		}
		session, err := manager.create(in)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 201, session.snapshot(0))
	})
	m.HandleFunc("GET /v1/terminal/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		session, ok := manager.get(r.PathValue("id"))
		if !ok {
			respond(w, 404, map[string]string{"error": "终端会话不存在或已回收"})
			return
		}
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		respond(w, 200, session.snapshot(after))
	})
	m.HandleFunc("POST /v1/terminal/sessions/{id}/input", func(w http.ResponseWriter, r *http.Request) {
		var in terminalInputRequest
		if !readJSON(w, r, &in) {
			return
		}
		data, err := base64.StdEncoding.DecodeString(in.Data)
		if err != nil {
			respond(w, 400, map[string]string{"error": "终端输入编码无效"})
			return
		}
		session, ok := manager.get(r.PathValue("id"))
		if !ok {
			respond(w, 404, map[string]string{"error": "终端会话不存在或已回收"})
			return
		}
		if err = session.write(data); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("POST /v1/terminal/sessions/{id}/resize", func(w http.ResponseWriter, r *http.Request) {
		var in terminalResizeRequest
		if !readJSON(w, r, &in) {
			return
		}
		session, ok := manager.get(r.PathValue("id"))
		if !ok {
			respond(w, 404, map[string]string{"error": "终端会话不存在或已回收"})
			return
		}
		if err := session.resize(in.Cols, in.Rows); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("DELETE /v1/terminal/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !manager.remove(r.PathValue("id")) {
			respond(w, 404, map[string]string{"error": "终端会话不存在或已回收"})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
}

func registerTerminalProxy(m *http.ServeMux, prefix, socket string) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	proxy := func(w http.ResponseWriter, r *http.Request) {
		target := strings.Replace(r.URL.RequestURI(), prefix, "/v1/terminal", 1)
		request, err := http.NewRequestWithContext(r.Context(), r.Method, "http://terminal"+target, http.MaxBytesReader(w, r.Body, 64*1024))
		if err != nil {
			respond(w, 500, map[string]string{"error": "终端代理请求无效"})
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			respond(w, 503, map[string]string{"error": "受限终端服务不可用"})
			return
		}
		defer response.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = io.CopyN(w, response.Body, 2*1024*1024)
	}
	for _, pattern := range []string{
		"POST " + prefix + "/sessions",
		"GET " + prefix + "/sessions/{id}",
		"POST " + prefix + "/sessions/{id}/input",
		"POST " + prefix + "/sessions/{id}/resize",
		"DELETE " + prefix + "/sessions/{id}",
	} {
		m.HandleFunc(pattern, proxy)
	}
}

// ServeTerminalSocket exposes only PTY routes and must run under the dedicated
// panel-task systemd identity. The root executor is the sole socket caller.
func ServeTerminalSocket(socket, username string) error {
	if username != "panel-task" && username != "root" {
		return errors.New("unsupported terminal identity")
	}
	account, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("terminal server must run as %s", username)
	}
	if socket == "" || socket[0] != '/' {
		return errors.New("terminal socket must be absolute")
	}
	if err = os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return err
	}
	if st, statErr := os.Lstat(socket); statErr == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket %s", socket)
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	mux := http.NewServeMux()
	registerTerminalHandler(mux, newTerminalManager(username))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	return server.Serve(listener)
}
