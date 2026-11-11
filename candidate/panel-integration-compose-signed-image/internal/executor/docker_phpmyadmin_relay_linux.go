//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// The Docker job can write only to its existing executor state tree.
const phpMyAdminRelayRoot = "/var/lib/panel-executor/phpmyadmin-db"

func phpMyAdminRelayUnit(id, serverID string) string {
	return "panel-phpmyadmin-db@" + id + "-" + serverID + ".service"
}

type phpMyAdminRelay struct {
	ProjectID string `json:"project_id"`
	ServerID  string `json:"mysql_server_id"`
}

func loadPhpMyAdminRelay(id string) (phpMyAdminRelay, error) {
	var relay phpMyAdminRelay
	dir, err := openComposeUpdateDirectory(phpMyAdminRelayRoot, id)
	if err != nil {
		return relay, err
	}
	defer dir.Close()
	raw, _, err := dir.read("metadata.json", 1024)
	if err != nil || json.Unmarshal(raw, &relay) != nil || relay.ProjectID != id || !core.ValidID(relay.ServerID) {
		return relay, errors.New("phpMyAdmin 本机数据库连接记录无效")
	}
	return relay, nil
}

func preparePhpMyAdminRelay(ctx context.Context, relay phpMyAdminRelay) error {
	server, err := readMySQL(relay.ServerID)
	if err != nil || !server.Ready {
		return errors.New("无法核对本机 MySQL 实例")
	}
	if err := os.MkdirAll(phpMyAdminRelayRoot, 0700); err != nil {
		return err
	}
	dir := filepath.Join(phpMyAdminRelayRoot, relay.ProjectID)
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := writeExclusiveJSON(filepath.Join(dir, "metadata.json"), relay); err != nil {
		_ = os.Remove(dir)
		return err
	}
	if _, err := loadPhpMyAdminRelay(relay.ProjectID); err != nil {
		return err
	}
	_, err = RunCommand(ctx, "/usr/bin/systemctl", "enable", "--now", phpMyAdminRelayUnit(relay.ProjectID, relay.ServerID))
	return err
}

func removePhpMyAdminRelay(ctx context.Context, metadata composeMetadata) error {
	relay, err := loadPhpMyAdminRelay(metadata.ID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || relay.ServerID != metadata.MySQLServerID {
		return errors.New("无法核对要关闭的 phpMyAdmin 数据库连接")
	}
	unit := phpMyAdminRelayUnit(metadata.ID, metadata.MySQLServerID)
	if _, err := RunCommand(ctx, "/usr/bin/systemctl", "disable", "--now", unit); err != nil {
		return err
	}
	if _, err := RunCommand(ctx, "/usr/bin/systemctl", "clean", "--what=runtime", unit); err != nil {
		return err
	}
	dir := filepath.Join(phpMyAdminRelayRoot, metadata.ID)
	retired := filepath.Join(phpMyAdminRelayRoot, ".retired-"+metadata.ID)
	if err := os.Rename(dir, retired); err != nil {
		return err
	}
	return os.RemoveAll(retired)
}

func ServePhpMyAdminRelay(instance string) error {
	id, serverID, ok := strings.Cut(instance, "-")
	if !ok || !core.ValidID(id) || !core.ValidID(serverID) || os.Geteuid() == 0 {
		return errors.New("phpMyAdmin 本机数据库连接身份无效")
	}
	account, err := user.Lookup(mysqlUser(serverID))
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errors.New("phpMyAdmin 本机数据库账户无效")
	}
	directory := core.PhpMyAdminSocketDirectory(id, serverID)
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0755 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("phpMyAdmin 连接套接字目录无效")
	}
	address := filepath.Join(directory, "mysql.sock")
	if previous, err := os.Lstat(address); err == nil {
		if previous.Mode().Type() != os.ModeSocket || previous.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errors.New("phpMyAdmin 连接套接字路径已被占用")
		}
		if err := os.Remove(address); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(address, 0666); err != nil {
		return err
	}
	notifier, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: os.Getenv("NOTIFY_SOCKET"), Net: "unixgram"})
	if err != nil {
		return err
	}
	_, err = notifier.Write([]byte("READY=1"))
	_ = notifier.Close()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	connections := make(chan struct{}, 64)
	for {
		client, err := listener.AcceptUnix()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case connections <- struct{}{}:
			go func() {
				defer func() { <-connections }()
				forwardPhpMyAdminConnection(ctx, client, mysqlSocket(serverID), uint32(uid))
			}()
		default:
			_ = client.Close()
		}
	}
}

func dialPhpMyAdminDatabase(ctx context.Context, address string, uid uint32) (*net.UnixConn, error) {
	parent, err := unix.Open(filepath.Dir(address), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	var info unix.Stat_t
	if err := unix.Fstat(parent, &info); err != nil || info.Uid != uid {
		return nil, errors.New("MySQL 套接字目录身份无效")
	}
	socket, err := unix.Openat(parent, filepath.Base(address), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(socket)
	if err := unix.Fstat(socket, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFSOCK || info.Uid != uid {
		return nil, errors.New("MySQL 套接字身份无效")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(socket))
	if err != nil {
		return nil, err
	}
	database := connection.(*net.UnixConn)
	raw, err := database.SyscallConn()
	if err == nil {
		var peer *unix.Ucred
		var peerErr error
		err = raw.Control(func(fd uintptr) {
			peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})
		if err == nil && peerErr == nil && peer != nil && peer.Uid == uid {
			return database, nil
		}
	}
	_ = database.Close()
	return nil, errors.New("无法核对 MySQL 套接字进程身份")
}

func forwardPhpMyAdminConnection(ctx context.Context, client *net.UnixConn, address string, uid uint32) {
	defer client.Close()
	database, err := dialPhpMyAdminDatabase(ctx, address, uid)
	if err != nil {
		return
	}
	defer database.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(database, client)
		_ = database.CloseWrite()
		close(done)
	}()
	_, _ = io.Copy(client, database)
	_ = client.CloseWrite()
	_ = client.CloseRead()
	<-done
}
