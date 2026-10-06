package main

import (
	"context"
	"flag"
	"local/panel/internal/core"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	data := flag.String("data", "/var/lib/panel", "state directory")
	web := flag.String("web", "/opt/panel/web", "static files")
	listen := flag.String("listen", "127.0.0.1:19100", "loopback listener")
	socket := flag.String("executor", "/run/panel-executor/control.sock", "executor socket")
	origin := flag.String("origin", "http://127.0.0.1:19100", "allowed browser origin")
	recoverAccount := flag.String("recover-account", "", "root-only local account recovery; read new password from stdin")
	flag.Parse()
	if *recoverAccount != "" {
		if e := recoverLocalAccount(*data, *recoverAccount); e != nil {
			log.Fatal(e)
		}
		log.Print("账户已恢复：密码已更新，双重验证与恢复码已清除，原有会话已撤销")
		return
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("development build only supports an explicit loopback listen address")
	}
	store, err := core.OpenStore(filepath.Join(*data, "panel.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.DB.Close()
	if err = store.Recover(); err != nil {
		log.Fatal(err)
	}
	app, err := core.NewServer(store, core.Config{DataDir: *data, WebDir: *web, Socket: *socket, Origin: *origin, Listen: *listen})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go core.RunWorker(ctx, store, app.Executor)
	app.StartAppDailyWorker(ctx)
	app.StartAnalyticsMaintenance(ctx)
	srv := &http.Server{Addr: *listen, Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 100 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		stop, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(stop)
	}()
	log.Printf("panel development server listening on %s", *listen)
	if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
