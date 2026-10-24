//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net"
	"strconv"
	"strings"
	"time"
)

const redisReplyByteLimit = 2 << 20
const redisReplyItemLimit = 1024
const redisCommandByteLimit = 128 << 10

var errRedisProtocol = errors.New("Redis 响应格式或容量无效")

type redisRESPReader struct {
	reader *bufio.Reader
	items  int
}

func newRedisRESPReader(input io.Reader) *redisRESPReader {
	return &redisRESPReader{reader: bufio.NewReaderSize(io.LimitReader(input, redisReplyByteLimit+1), 4096)}
}

func (r *redisRESPReader) line() (string, error) {
	raw, err := r.reader.ReadSlice('\n')
	if err != nil || len(raw) < 2 || len(raw) > 4096 || raw[len(raw)-2] != '\r' {
		return "", errRedisProtocol
	}
	line := string(raw[:len(raw)-2])
	if strings.ContainsAny(line, "\r\n") {
		return "", errRedisProtocol
	}
	return line, nil
}

func redisReplyNumber(raw string) (int64, error) {
	if raw == "" || (len(raw) > 1 && raw[0] == '0') || strings.HasPrefix(raw, "+") {
		return 0, errRedisProtocol
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != raw {
		return 0, errRedisProtocol
	}
	return n, nil
}

func (r *redisRESPReader) value(depth int) (any, error) {
	r.items++
	if depth > 8 || r.items > redisReplyItemLimit {
		return nil, errRedisProtocol
	}
	kind, err := r.reader.ReadByte()
	if err != nil {
		return nil, errRedisProtocol
	}
	line, err := r.line()
	if err != nil {
		return nil, err
	}
	switch kind {
	case '+':
		return line, nil
	case '-':
		// A peer must not echo secret AUTH arguments or user data into public errors.
		code := strings.SplitN(line, " ", 2)[0]
		switch code {
		case "NOAUTH", "WRONGPASS", "NOPERM", "WRONGTYPE", "OOM", "BUSY", "READONLY", "MISCONF", "NOSCRIPT", "EXECABORT":
		default:
			code = "ERR"
		}
		return nil, fmt.Errorf("Redis 请求被拒绝（%s）", code)
	case ':':
		return redisReplyNumber(line)
	case '$':
		n, err := redisReplyNumber(line)
		if err != nil || n < -1 || n > 1<<20 {
			return nil, errRedisProtocol
		}
		if n == -1 {
			return nil, nil
		}
		raw := make([]byte, int(n)+2)
		if _, err = io.ReadFull(r.reader, raw); err != nil || raw[n] != '\r' || raw[n+1] != '\n' {
			return nil, errRedisProtocol
		}
		return string(raw[:n]), nil
	case '*':
		n, err := redisReplyNumber(line)
		if err != nil || n < -1 || n > redisReplyItemLimit-int64(r.items) {
			return nil, errRedisProtocol
		}
		if n == -1 {
			return nil, nil
		}
		values := make([]any, 0, int(n))
		for i := int64(0); i < n; i++ {
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			values = append(values, v)
		}
		return values, nil
	}
	return nil, errRedisProtocol
}

func redisRESPCommand(args []string) ([]byte, error) {
	if len(args) == 0 || len(args) > 64 {
		return nil, errors.New("Redis 命令参数无效")
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "*%d\r\n", len(args))
	for _, arg := range args {
		if len(arg) > redisCommandByteLimit || out.Len()+len(arg)+32 > redisCommandByteLimit {
			return nil, errors.New("Redis 命令容量超出限制")
		}
		fmt.Fprintf(&out, "$%d\r\n", len(arg))
		out.WriteString(arg)
		out.WriteString("\r\n")
	}
	return out.Bytes(), nil
}

func redisRESPRoundTrip(conn net.Conn, reader *redisRESPReader, args []string) (any, error) {
	raw, err := redisRESPCommand(args)
	if err != nil {
		return nil, err
	}
	for len(raw) > 0 {
		n, err := conn.Write(raw)
		if err != nil || n <= 0 {
			return nil, errors.New("Redis 连接写入失败")
		}
		raw = raw[n:]
	}
	return reader.value(0)
}

// One private connection; AUTH, SELECT and command share the same deadline and
// cancellation. Passwords never enter argv, environment, logs or shell syntax.
// Protocol: https://redis.io/docs/latest/develop/reference/protocol-spec/
func redisAuthenticatedCommand(ctx context.Context, conn net.Conn, username, password string, db int, command ...string) (any, error) {
	if db < 0 || db > 15 || username == "" || !validRedisPassword(password) {
		return nil, errors.New("Redis 认证请求无效")
	}
	if len(command) == 0 {
		return nil, errors.New("Redis 命令为空")
	}
	switch command[0] {
	case "PING", "INFO", "EVAL", "UNLINK", "SCAN", "TYPE", "TTL", "STRLEN", "LLEN", "HLEN", "SCARD", "ZCARD", "XLEN":
	default:
		return nil, errors.New("Redis 管理命令不在固定范围")
	}
	if _, err := redisRESPCommand(command); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, errors.New("Redis 连接时限设置失败")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	reader := newRedisRESPReader(conn)
	result, err := redisRESPRoundTrip(conn, reader, []string{"AUTH", username, password})
	if err != nil || result != "OK" {
		return nil, errors.New("Redis 认证失败，未执行命令")
	}
	if db != 0 {
		result, err = redisRESPRoundTrip(conn, reader, []string{"SELECT", strconv.Itoa(db)})
		if err != nil || result != "OK" {
			return nil, errors.New("Redis 逻辑库选择失败，未执行命令")
		}
	}
	return redisRESPRoundTrip(conn, reader, command)
}

func redisSecureValue(ctx context.Context, instance core.RedisInstance, db int, command ...string) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	secret, err := readRedisAuth(instance)
	if err != nil {
		return nil, err
	}
	defer func() { secret.AdminPassword = ""; secret.AppPassword = "" }()
	conn, err := dialRedisManagement(ctx, instance)
	if err != nil {
		return nil, errRedisPeer
	}
	defer conn.Close()
	return redisAuthenticatedCommand(ctx, conn, "panel-admin", secret.AdminPassword, db, command...)
}

func redisSecureJSON(ctx context.Context, instance core.RedisInstance, db int, out any, command ...string) error {
	value, err := redisSecureValue(ctx, instance, db, command...)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return errRedisProtocol
	}
	if json.Unmarshal(raw, out) != nil {
		return errRedisProtocol
	}
	return nil
}

func redisInfoText(ctx context.Context, instance core.RedisInstance, command ...string) (string, error) {
	if err := validateRedisAuthMode(instance); err != nil {
		return "", err
	}
	if instance.AuthMode == core.RedisACLAuthMode {
		v, err := redisSecureValue(ctx, instance, 0, command...)
		if err != nil {
			return "", err
		}
		text, ok := v.(string)
		if !ok {
			return "", errRedisProtocol
		}
		return text, nil
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "redis" {
		return "", errors.New("Redis 版本不在固定目录")
	}
	args := append([]string{"-h", "127.0.0.1", "-p", strconv.Itoa(instance.Port)}, command...)
	return RunCommand(ctx, release.Prefix()+"/bin/redis-cli", args...)
}
