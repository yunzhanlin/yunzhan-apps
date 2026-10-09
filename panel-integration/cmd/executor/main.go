//go:build linux

package main

import (
	"context"
	"flag"
	"local/panel/internal/executor"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type peerKey struct{}

func main() {
	socket := flag.String("socket", "/run/panel-executor/control.sock", "Unix socket")
	install := flag.String("install-job", "", "run a reviewed runtime installation job")
	prepare := flag.String("prepare-site", "", "create an isolated site account")
	servePHP := flag.String("serve-php", "", "serve one managed PHP pool")
	siteCLI := flag.String("site-cli", "", "run the CLI bound to this site")
	nginxOp := flag.String("nginx-operation", "", "execute a fixed Nginx service operation")
	nginxRollback := flag.String("nginx-rollback", "", "recover an uncommitted Nginx change")
	recoverNginx := flag.Bool("recover-nginx", false, "restore unfinished Nginx selections at boot")
	firewallRollback := flag.String("firewall-rollback", "", "recover an unconfirmed firewall change")
	recoverFirewall := flag.Bool("recover-firewall", false, "restore unfinished firewall changes at boot")
	restoreSystem := flag.String("restore-system", "", "decrypt and verify a system backup into an empty root")
	restoreRoot := flag.String("restore-root", "", "empty destination root for a system restore")
	passphraseFile := flag.String("passphrase-file", "", "0600 file containing the system backup passphrase")
	mysqlPrepare := flag.String("prepare-mysql", "", "create an isolated database account")
	mysqlServe := flag.String("serve-mysql", "", "serve an isolated database instance")
	mysqlJob := flag.String("database-job", "", "run a managed database operation")
	mysqlCLI := flag.String("database-cli", "", "run a local root database client")
	mysqlOverwriteRecovery := flag.Bool("recover-database-overwrites", false, "recover interrupted database replacement operations")
	terminalServer := flag.String("terminal-server", "", "serve restricted terminal sessions on a private Unix socket")
	terminalUser := flag.String("terminal-user", "panel-task", "fixed identity for terminal-server")
	sftpJob := flag.String("sftp-job", "", "run one root-only SFTP account job")
	dockerJob := flag.String("docker-job", "", "run one Docker image or container job")
	composeJob := flag.String("compose-job", "", "run one managed Docker Compose project job")
	recoverCompose := flag.Bool("recover-compose", false, "clean interrupted Docker Compose operations")
	redisServe := flag.String("serve-redis", "", "serve one managed Redis instance")
	mariadbServe := flag.String("serve-mariadb", "", "serve one managed MariaDB instance")
	mariadbInit := flag.String("init-mariadb", "", "initialize one managed MariaDB data directory")
	nodeServe := flag.String("serve-node", "", "serve one managed Node.js application")
	appDependencies := flag.String("install-app-dependencies", "", "install fixed module dependencies")
	wafEngineBuild := flag.String("build-waf-engine", "", "build a pinned independent WAF engine without activating sites")
	wafEngineVerify := flag.String("verify-waf-engine", "", "verify a built WAF program without activating or changing sites")
	analyticsHTMLBuild := flag.String("build-analytics-html", "", "build a pinned isolated analytics HTML engine without activating sites")
	wafRecover := flag.Bool("recover-waf-config", false, "restore an interrupted WAF configuration before Nginx startup")
	apacheWAFRecover := flag.Bool("recover-apache-waf-config", false, "restore interrupted Apache WAF configuration before Apache startup")
	pm2Serve := flag.String("serve-pm2", "", "serve one isolated PM2 application")
	pm2Deploy := flag.String("pm2-deploy", "", "deploy locked dependencies for one managed PM2 application")
	ftpServe := flag.Bool("serve-ftp", false, "serve the fixed managed FTPS configuration")
	ftpRecover := flag.Bool("recover-ftp", false, "recover interrupted FTPS configuration before boot")
	nfsMount := flag.String("mount-nfs", "", "mount a managed NFS share")
	nfsUnmount := flag.String("unmount-nfs", "", "unmount a managed NFS share")
	nfsServe := flag.Bool("serve-nfs-server", false, "serve private NFSv4 website exports")
	nfsRecover := flag.Bool("recover-nfs-server", false, "recover unfinished NFSv4 export configuration")
	flag.Parse()
	if *mariadbInit != "" {
		if e := executor.InitMariaDB(*mariadbInit); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *terminalServer != "" {
		if e := executor.ServeTerminalSocket(*terminalServer, *terminalUser); e != nil {
			log.Fatal(e)
		}
		return
	}
	if os.Geteuid() != 0 {
		log.Fatal("executor must run under its root systemd unit")
	}
	if *wafRecover {
		if err := executor.RecoverWAFConfiguration(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *apacheWAFRecover {
		if err := executor.RecoverApacheWAFConfiguration(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *ftpRecover {
		if e := executor.RecoverPureFTP(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *nfsRecover {
		if e := executor.RecoverNFSServer(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *nfsServe {
		if e := executor.ServeNFSServer(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *ftpServe {
		if e := executor.ServePureFTP(); e != nil {
			log.Fatal(e)
		}
		return
	}
	for _, operation := range []struct {
		id  string
		run func(string) error
	}{{*appDependencies, executor.InstallAppDependencies}, {*wafEngineBuild, executor.RunWAFEngineBuild}, {*wafEngineVerify, executor.VerifyWAFEngineBuild}, {*analyticsHTMLBuild, executor.RunAnalyticsHTMLBuild}, {*pm2Serve, executor.ServePM2}, {*pm2Deploy, executor.RunPM2Dependencies}, {*nfsMount, func(id string) error { return executor.NFSMountOperation(id, false) }}, {*nfsUnmount, func(id string) error { return executor.NFSMountOperation(id, true) }}} {
		if operation.id != "" {
			if e := operation.run(operation.id); e != nil {
				log.Fatal(e)
			}
			return
		}
	}
	if *sftpJob != "" {
		if e := executor.RunSFTPJob(*sftpJob); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *dockerJob != "" {
		if e := executor.RunDockerJob(*dockerJob); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *composeJob != "" {
		if e := executor.RunComposeJob(*composeJob); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *recoverCompose {
		if e := executor.RecoverComposeJobs(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *redisServe != "" {
		if e := executor.ServeRedis(*redisServe); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *mariadbServe != "" {
		if e := executor.ServeMariaDB(*mariadbServe); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *nodeServe != "" {
		if e := executor.ServeNode(*nodeServe); e != nil {
			log.Fatal(e)
		}
		return
	}
	for _, op := range []struct {
		id  string
		run func(string) error
	}{{*mysqlPrepare, executor.PrepareMySQLUser}, {*mysqlServe, executor.ServeMySQL}, {*mysqlJob, executor.RunDatabaseJob}} {
		if op.id != "" {
			if e := op.run(op.id); e != nil {
				log.Fatal(e)
			}
			return
		}
	}
	if *mysqlCLI != "" {
		if e := executor.DatabaseCLI(*mysqlCLI, flag.Args()); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *mysqlOverwriteRecovery {
		if e := executor.RecoverDatabaseOverwrites(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *nginxOp != "" {
		if e := executor.NginxCommand(*nginxOp); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *nginxRollback != "" {
		if e := executor.NginxRollback(*nginxRollback); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *recoverNginx {
		if e := executor.RecoverNginx(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *firewallRollback != "" {
		if e := executor.FirewallRollback(*firewallRollback); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *recoverFirewall {
		if e := executor.RecoverFirewall(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *restoreSystem != "" {
		if *restoreRoot == "" || *passphraseFile == "" {
			log.Fatal("restore-root and passphrase-file are required")
		}
		if e := executor.RestoreSystemBackup(*restoreSystem, *passphraseFile, *restoreRoot); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *prepare != "" {
		if err := executor.PrepareSiteUser(*prepare); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *servePHP != "" {
		if err := executor.ServePHP(*servePHP); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *siteCLI != "" {
		if err := executor.SiteCLI(*siteCLI, flag.Args()); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *install != "" {
		if err := executor.InstallJob(*install); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := executor.RecoverApacheWAFConfiguration(); err != nil {
		log.Fatal(err)
	}
	account, err := user.Lookup("panel")
	if err != nil {
		log.Fatal(err)
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if err = os.MkdirAll(filepath.Dir(*socket), 0750); err != nil {
		log.Fatal(err)
	}
	if err = os.Chown(filepath.Dir(*socket), 0, gid); err != nil {
		log.Fatal(err)
	}
	if st, err := os.Lstat(*socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			log.Fatal("refusing to replace a non-socket")
		}
		if err = os.Remove(*socket); err != nil {
			log.Fatal(err)
		}
	}
	l, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	if err = os.Chown(*socket, 0, gid); err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(*socket, 0660); err != nil {
		log.Fatal(err)
	}
	svc := executor.New(executor.Config{SitesDir: "/srv/panel/sites", ConfDir: "/etc/panel/sites-enabled", StateDir: "/var/lib/panel-executor", NginxBin: "/usr/sbin/nginx", TerminalSocket: "/run/panel-terminal/control.sock", RootTerminalSocket: "/run/panel-terminal-root/control.sock"})
	handler := svc.Handler()
	if err = svc.StartPHPWorkerOperations(); err != nil {
		log.Fatal(err)
	}
	svc.StartAppModuleWorker()
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			peer := -1
			if un, ok := c.(*net.UnixConn); ok {
				if raw, er := un.SyscallConn(); er == nil {
					_ = raw.Control(func(fd uintptr) {
						if cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); e == nil {
							peer = int(cred.Uid)
						}
					})
				}
			}
			return context.WithValue(ctx, peerKey{}, peer)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, _ := r.Context().Value(peerKey{}).(int)
			if peer != uid && peer != 0 {
				http.Error(w, "forbidden peer", 403)
				return
			}
			handler.ServeHTTP(w, r)
		})}
	log.Print("executor ready on private Unix socket")
	if err = server.Serve(l); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
