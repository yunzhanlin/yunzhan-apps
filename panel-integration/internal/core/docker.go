package core

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var dockerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
var dockerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
var dockerImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
var dockerEnvPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func validDockerResourceName(name string) bool { return dockerNamePattern.MatchString(name) }

type DockerPort struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type DockerEnvironment struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DockerJobRequest struct {
	JobID       string              `json:"job_id"`
	Action      string              `json:"action"`
	Image       string              `json:"image"`
	Name        string              `json:"name,omitempty"`
	Restart     string              `json:"restart,omitempty"`
	Ports       []DockerPort        `json:"ports,omitempty"`
	Environment []DockerEnvironment `json:"environment,omitempty"`
	Command     []string            `json:"command,omitempty"`
}

type DockerJobResult struct {
	JobID       string `json:"job_id"`
	Kind        string `json:"kind,omitempty"`
	State       string `json:"state"`
	Error       string `json:"error,omitempty"`
	Message     string `json:"message,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	Image       string `json:"image,omitempty"`
}

type DockerProjectRequest struct {
	JobID      string `json:"job_id"`
	ProjectID  string `json:"project_id"`
	Action     string `json:"action"`
	Name       string `json:"name,omitempty"`
	Compose    string `json:"compose,omitempty"`
	TemplateID string `json:"template_id,omitempty"`
}

func dockerTemplate(id string, port int) (string, error) {
	if port < 1024 || port > 65535 {
		return "", errors.New("应用模板主机端口应为 1024–65535")
	}
	if _, ok := LegacyPHPImages[id]; ok {
		return isolatedPHPTemplate(id, port), nil
	}
	switch id {
	case "rabbitmq":
		if port == 65535 {
			return "", errors.New("双端口应用的起始端口不能为 65535")
		}
		password := Token()
		return fmt.Sprintf(`services:
  rabbitmq:
    image: rabbitmq:4.1.4-management-alpine@sha256:5cbd7145b0306399ad68422c3350b6cbd1bb95704b39f5896480e5b6d4238a04
    restart: unless-stopped
    hostname: cloudstack-rabbitmq
    environment:
      RABBITMQ_DEFAULT_USER: paneladmin
      RABBITMQ_DEFAULT_PASS: "%s"
      RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS: "+S 2:2 +SDcpu 1 +SDio 1"
    mem_limit: 512m
    ports:
      - "127.0.0.1:%d:15672"
      - "127.0.0.1:%d:5672"
    volumes:
      - data:/var/lib/rabbitmq
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "check_running"]
      interval: 15s
      timeout: 20s
      retries: 20
      start_period: 120s
volumes:
  data: {}
`, password, port, port+1), nil
	case "openlitespeed":
		if port == 65535 {
			return "", errors.New("双端口应用的起始端口不能为 65535")
		}
		password := Token()
		bootstrap := `set -eu
if [ -z "$(ls -A /usr/local/lsws/conf)" ]; then cp -R /usr/local/lsws/.conf/. /usr/local/lsws/conf/; fi
if [ -z "$(ls -A /usr/local/lsws/admin/conf)" ]; then cp -R /usr/local/lsws/admin/.conf/. /usr/local/lsws/admin/conf/; fi
if [ ! -d /var/www/vhosts/cloudstack/html ]; then
  mkdir -p /var/www/vhosts/cloudstack
  cp -R /usr/local/lsws/Example/. /var/www/vhosts/cloudstack/
fi
sed -i 's#vhRoot[[:space:]]*Example/#vhRoot /var/www/vhosts/cloudstack/#' /usr/local/lsws/conf/httpd_config.conf
HASH=$(/usr/local/lsws/admin/fcgi-bin/admin_php -q /usr/local/lsws/admin/misc/htpasswd.php "$CLOUDSTACK_ADMIN_PASSWORD")
printf 'admin:%s\n' "$HASH" > /usr/local/lsws/admin/conf/htpasswd
chmod 600 /usr/local/lsws/admin/conf/htpasswd
exec /entrypoint.sh
`
		return fmt.Sprintf(`services:
  openlitespeed:
    image: litespeedtech/openlitespeed:1.8.4-lsphp83@sha256:6f50ba204e66f1c746dd183f3022340ca912124c414669755db7f4701167f268
    restart: unless-stopped
    entrypoint: ["/bin/sh", "-c"]
    command: [%s]
    environment:
      CLOUDSTACK_ADMIN_PASSWORD: "%s"
    mem_limit: 512m
    ports:
      - "127.0.0.1:%d:8088"
      - "127.0.0.1:%d:7080"
    volumes:
      - server-conf:/usr/local/lsws/conf
      - admin-conf:/usr/local/lsws/admin/conf
      - site-data:/var/www/vhosts
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:8088/ >/dev/null"]
      interval: 15s
      timeout: 10s
      retries: 18
      start_period: 60s
volumes:
  server-conf: {}
  admin-conf: {}
  site-data: {}
`, strconv.Quote(strings.ReplaceAll(bootstrap, "$", "$$")), password, port, port+1), nil
	case "nginx-static":
		return "services:\n  web:\n    image: nginx:1.28.0-alpine\n    restart: unless-stopped\n    ports:\n      - \"127.0.0.1:" + strconv.Itoa(port) + ":80\"\n", nil
	case "redis-cache":
		return "services:\n  redis:\n    image: redis:8.2.9-alpine\n    restart: unless-stopped\n    ports:\n      - \"127.0.0.1:" + strconv.Itoa(port) + ":6379\"\n    volumes:\n      - data:/data\nvolumes:\n  data: {}\n", nil
	case "memcached-cache":
		return "services:\n  memcached:\n    image: memcached:1.6.45-alpine\n    restart: unless-stopped\n    command: [\"memcached\", \"-m\", \"128\", \"-I\", \"4m\"]\n    ports:\n      - \"127.0.0.1:" + strconv.Itoa(port) + ":11211\"\n    healthcheck:\n      test: [\"CMD-SHELL\", \"printf 'version\\r\\n' | nc -w 2 127.0.0.1 11211 | grep -q '^VERSION'\"]\n      interval: 10s\n      timeout: 3s\n      retries: 12\n", nil
	case "phpmyadmin":
		return fmt.Sprintf(`services:
  phpmyadmin:
    image: phpmyadmin:5.2.2-apache@sha256:6b5ab5f9ebfe3dbb38388b5695c2ff5ba3e26cdc2c4ce0bd97092eefc6a20bfd
    restart: unless-stopped
    environment:
      PMA_ARBITRARY: "1"
      UPLOAD_LIMIT: "256M"
    ports:
      - "127.0.0.1:%d:80"
    healthcheck:
      test: ["CMD-SHELL", "php -r '$$s=@fsockopen(\"127.0.0.1\",80); exit($$s?0:1);'"]
      interval: 10s
      timeout: 5s
      retries: 18
      start_period: 30s
`, port), nil
	case "mongodb":
		password := Token()
		return fmt.Sprintf(`services:
  mongodb:
    image: mongo:8.0@sha256:d0d926f94df099bff534b7ee5b5986458131a22489dfff8664509af0c1e2ca9c
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: paneladmin
      MONGO_INITDB_ROOT_PASSWORD: "%s"
    ports:
      - "127.0.0.1:%d:27017"
    volumes:
      - data:/data/db
    healthcheck:
      test: ["CMD-SHELL", "mongosh --username paneladmin --password '%s' --authenticationDatabase admin --quiet --eval 'quit(db.adminCommand({ping:1}).ok ? 0 : 2)'"]
      interval: 15s
      timeout: 20s
      retries: 18
      start_period: 60s
volumes:
  data: {}
`, password, port, password), nil
	case "elasticsearch":
		return fmt.Sprintf(`services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:9.1.4@sha256:62a245d92e8d14440e1e43a1b4f08d37aef316d82f198b4f878985948aa2d1d8
    restart: unless-stopped
    environment:
      discovery.type: single-node
      xpack.security.enabled: "false"
      node.store.allow_mmap: "false"
      ES_JAVA_OPTS: "-Xms512m -Xmx512m"
    mem_limit: 1g
    ports:
      - "127.0.0.1:%d:9200"
    volumes:
      - data:/usr/share/elasticsearch/data
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null"]
      interval: 15s
      timeout: 15s
      retries: 20
      start_period: 15m
volumes:
  data: {}
`, port), nil
	case "node-service":
		return "services:\n  app:\n    image: node:24.21.0-alpine\n    restart: unless-stopped\n    command: [\"node\", \"-e\", \"require('http').createServer((q,s)=>s.end('Node.js managed by YunZhan')).listen(3000)\"]\n    ports:\n      - \"127.0.0.1:" + strconv.Itoa(port) + ":3000\"\n", nil
	case "wordpress-blog":
		// Both secrets exist only in the root-owned Compose request and project file.
		// Never return the generated YAML from the API or add it to the audit log.
		dbPassword, rootPassword := Token(), Token()
		return fmt.Sprintf(`services:
  db:
    image: mariadb:11.8.9
    restart: unless-stopped
    environment:
      MARIADB_DATABASE: wordpress
      MARIADB_USER: wpuser
      MARIADB_PASSWORD: "%s"
      MARIADB_ROOT_PASSWORD: "%s"
    volumes:
      - db-data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 60s
  wordpress:
    image: wordpress:7.1.2-php8.3-apache
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wpuser
      WORDPRESS_DB_PASSWORD: "%s"
      WORDPRESS_DB_NAME: wordpress
    ports:
      - "127.0.0.1:%d:80"
    volumes:
      - wordpress-data:/var/www/html
volumes:
  db-data: {}
  wordpress-data: {}
`, dbPassword, rootPassword, dbPassword, port), nil
	default:
		return "", errors.New("应用模板不存在")
	}
}

func ValidateDockerProject(v DockerProjectRequest) error {
	if !ValidID(v.JobID) || !ValidID(v.ProjectID) {
		return errors.New("Compose 作业标识无效")
	}
	switch v.Action {
	case "create":
		if !validDockerResourceName(v.Name) || len(v.Name) > 40 || len(v.Compose) < 20 || len(v.Compose) > 48*1024 || strings.ContainsRune(v.Compose, 0) {
			return errors.New("Compose 项目名称或内容无效")
		}
		if v.TemplateID != "" && !IsDockerTemplate(v.TemplateID) {
			return errors.New("应用模板不存在")
		}
	case "start", "stop", "restart", "update":
		if v.Name != "" || v.Compose != "" || v.TemplateID != "" {
			return errors.New("Compose 操作包含多余参数")
		}
	case "delete":
		if !validDockerResourceName(v.Name) || v.Compose != "" || v.TemplateID != "" {
			return errors.New("Compose 删除确认无效")
		}
	default:
		return errors.New("Compose 作业动作无效")
	}
	return nil
}

func ValidateDockerJob(v DockerJobRequest) error {
	if !ValidID(v.JobID) || !dockerImagePattern.MatchString(v.Image) || len(v.Image) > 200 {
		return errors.New("Docker 作业身份或镜像名称无效")
	}
	if v.Action == "pull" {
		if v.Name != "" || v.Restart != "" || len(v.Ports) != 0 || len(v.Environment) != 0 || len(v.Command) != 0 {
			return errors.New("镜像拉取包含多余参数")
		}
		return nil
	}
	if v.Action != "create" || !dockerNamePattern.MatchString(v.Name) {
		return errors.New("Docker 作业动作或容器名称无效")
	}
	if v.Restart != "no" && v.Restart != "unless-stopped" && v.Restart != "on-failure" {
		return errors.New("容器重启策略无效")
	}
	if len(v.Ports) > 16 || len(v.Environment) > 64 || len(v.Command) > 32 {
		return errors.New("端口或环境变量数量超过限制")
	}
	seenPorts, seenEnv := map[string]bool{}, map[string]bool{}
	for _, p := range v.Ports {
		if p.HostPort < 1024 || p.HostPort > 65535 || p.ContainerPort < 1 || p.ContainerPort > 65535 || (p.Protocol != "tcp" && p.Protocol != "udp") {
			return errors.New("容器端口映射无效")
		}
		key := strings.Join([]string{p.Protocol, strconv.Itoa(p.HostPort), strconv.Itoa(p.ContainerPort)}, ":")
		if seenPorts[key] {
			return errors.New("容器端口映射重复")
		}
		seenPorts[key] = true
	}
	for _, item := range v.Environment {
		if !dockerEnvPattern.MatchString(item.Name) || len(item.Value) > 4096 || strings.ContainsRune(item.Value, 0) || seenEnv[item.Name] {
			return errors.New("容器环境变量无效或重复")
		}
		seenEnv[item.Name] = true
	}
	for _, arg := range v.Command {
		if arg == "" || len(arg) > 512 || strings.ContainsRune(arg, 0) {
			return errors.New("容器命令参数无效")
		}
	}
	return nil
}

func validDockerObjectID(id string) bool { return dockerIDPattern.MatchString(id) }

func (a *Server) dockerRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/docker/projects/{id}/credentials", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var out any
		if e := a.Executor.Call(r.Context(), "GET", "/v1/docker/projects/"+r.PathValue("id")+"/credentials", nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.credentials.read", r.PathValue("id"), "success")
		w.Header().Set("Cache-Control", "no-store")
		send(w, 200, out)
	}))
	proxyGet := func(public, internal string) {
		m.HandleFunc("GET "+public, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			var out any
			if e := a.Executor.Call(r.Context(), http.MethodGet, internal, nil, &out); e != nil {
				fail(w, 503, e.Error())
				return
			}
			send(w, 200, out)
		}))
	}
	proxyGet("/api/docker", "/v1/docker")
	proxyGet("/api/docker/containers", "/v1/docker/containers")
	proxyGet("/api/docker/images", "/v1/docker/images")
	proxyGet("/api/docker/networks", "/v1/docker/networks")
	proxyGet("/api/docker/volumes", "/v1/docker/volumes")
	m.HandleFunc("GET /api/docker/projects", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var listed struct {
			Projects []map[string]any `json:"projects"`
		}
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/projects", nil, &listed); e != nil {
			fail(w, 503, e.Error())
			return
		}
		for _, project := range listed.Projects {
			id, _ := project["id"].(string)
			if !ValidID(id) {
				continue
			}
			name, e := a.Store.ProjectSiteReference(id)
			if e != nil {
				fail(w, 500, "读取应用网站绑定失败")
				return
			}
			project["site_name"] = name
		}
		send(w, 200, listed)
	}))
	m.HandleFunc("POST /api/docker/projects/{id}/sites", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		projectID := r.PathValue("id")
		if !ValidID(projectID) {
			fail(w, 400, "Compose 项目标识无效")
			return
		}
		var in struct {
			Name   string `json:"name"`
			Slug   string `json:"slug"`
			Domain string `json:"domain"`
		}
		if !decode(w, r, &in) {
			return
		}
		var listed struct {
			Projects []struct {
				ID         string `json:"id"`
				TemplateID string `json:"template_id"`
				HostPort   int    `json:"host_port"`
				State      string `json:"state"`
				Services   int    `json:"services"`
				Running    int    `json:"running"`
				Healthy    int    `json:"healthy"`
			} `json:"projects"`
		}
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/projects", nil, &listed); e != nil {
			fail(w, 503, e.Error())
			return
		}
		for _, project := range listed.Projects {
			if project.ID != projectID {
				continue
			}
			_, legacy := LegacyPHPImages[project.TemplateID]
			bindable := project.TemplateID == "wordpress-blog" || project.TemplateID == "openlitespeed" || legacy
			if !bindable || project.State != "running" || project.Services == 0 || project.Running != project.Services || project.Healthy != project.Services || project.HostPort < 1024 || project.HostPort > 65535 {
				fail(w, 409, "仅能绑定已通过健康检查的 WordPress、隔离 PHP 或 OpenLiteSpeed 模板")
				return
			}
			jobID, e := a.Store.CreateAppProxySite(strings.TrimSpace(in.Name), in.Slug, in.Domain, projectID, project.HostPort, r.Header.Get("Idempotency-Key"), u.Username)
			if e != nil {
				fail(w, 409, e.Error())
				return
			}
			send(w, 202, map[string]string{"job_id": jobID})
			return
		}
		fail(w, 404, "Compose 项目不存在")
	}))
	m.HandleFunc("GET /api/docker/templates", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		templates := []map[string]any{
			{"id": "nginx-static", "name": "Nginx 静态网站", "image": "nginx:1.28.0-alpine", "description": "回环端口提供官方 Nginx 默认站点", "container_port": 80},
			{"id": "redis-cache", "name": "Redis 缓存", "image": "redis:8.2.9-alpine", "description": "带持久命名卷的 Redis 单实例", "container_port": 6379},
			{"id": "memcached-cache", "name": "Memcached 缓存", "image": "memcached:1.6.45-alpine", "description": "128 MB 内存上限，只通过主机回环端口访问", "container_port": 11211},
			{"id": "phpmyadmin", "name": "phpMyAdmin", "image": "phpmyadmin:5.2.2-apache@sha256:6b5ab5f…", "description": "固定摘要镜像，只通过主机回环端口访问", "container_port": 80},
			{"id": "mongodb", "name": "MongoDB", "image": "mongo:8.0@sha256:d0d926f…", "description": "启用认证与持久卷的 MongoDB 8.0 单实例", "container_port": 27017},
			{"id": "elasticsearch", "name": "Elasticsearch", "image": "elasticsearch:9.1.4@sha256:62a245d…", "description": "1 GiB 容器上限、512 MiB JVM 的单节点检索服务", "container_port": 9200},
			{"id": "node-service", "name": "Node.js 服务", "image": "node:24.21.0-alpine", "description": "可直接访问的 Node.js HTTP 示例", "container_port": 3000},
			{"id": "wordpress-blog", "name": "WordPress 博客", "image": "wordpress:7.1.2-php8.3-apache + mariadb:11.8.9", "description": "独立 PHP 8.3 + MariaDB，持久卷保存网站与数据", "container_port": 80},
			{"id": "rabbitmq", "name": "RabbitMQ", "image": "rabbitmq:4.1.4-management-alpine", "description": "认证消息队列与管理后台，持久数据卷", "container_port": 15672},
			{"id": "openlitespeed", "name": "OpenLiteSpeed", "image": "litespeedtech/openlitespeed:1.8.4-lsphp83", "description": "独立网站与 HTTPS 管理后台，随机管理员密码", "container_port": 8088},
		}
		for _, version := range []string{"52", "53", "54", "55", "56", "70", "71", "72", "73", "74", "80", "81"} {
			id := "php-legacy-" + version
			templates = append(templates, map[string]any{"id": id, "name": "PHP " + version[:1] + "." + version[1:] + " 隔离环境", "image": LegacyPHPImages[id], "description": "已停止官方维护；独立 PHP-FPM + Nginx，仅回环端口，不接触主机网站目录", "container_port": 8080})
		}
		send(w, 200, map[string]any{"templates": templates})
	}))
	m.HandleFunc("POST /api/docker/projects", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Name       string `json:"name"`
			TemplateID string `json:"template_id"`
			HostPort   int    `json:"host_port"`
			Compose    string `json:"compose"`
		}
		if !decode(w, r, &in) {
			return
		}
		compose := in.Compose
		if in.TemplateID != "" {
			if compose != "" {
				fail(w, 400, "模板和自定义 Compose 不能同时提交")
				return
			}
			var e error
			compose, e = dockerTemplate(in.TemplateID, in.HostPort)
			if e != nil {
				fail(w, 400, e.Error())
				return
			}
		}
		op := DockerProjectRequest{JobID: ID(), ProjectID: ID(), Action: "create", Name: in.Name, Compose: compose, TemplateID: in.TemplateID}
		if e := ValidateDockerProject(op); e != nil {
			fail(w, 400, e.Error())
			return
		}
		var out DockerJobResult
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/projects/jobs", op, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.compose.create", in.Name, "queued")
		send(w, 202, out)
	}))
	m.HandleFunc("GET /api/docker/projects/{id}/logs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) {
			fail(w, 400, "Compose 项目标识无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/projects/"+r.PathValue("id")+"/logs", nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/docker/projects/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		op := DockerProjectRequest{JobID: ID(), ProjectID: r.PathValue("id"), Action: r.PathValue("action")}
		if e := ValidateDockerProject(op); e != nil {
			fail(w, 400, e.Error())
			return
		}
		var out DockerJobResult
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/projects/jobs", op, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.compose."+op.Action, op.ProjectID, "queued")
		send(w, 202, out)
	}))
	m.HandleFunc("DELETE /api/docker/projects/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		op := DockerProjectRequest{JobID: ID(), ProjectID: r.PathValue("id"), Action: "delete", Name: in.ConfirmName}
		if e := ValidateDockerProject(op); e != nil {
			fail(w, 409, "请输入项目名称确认删除")
			return
		}
		boundSite, e := a.Store.ProjectSiteReference(op.ProjectID)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		if boundSite != "" {
			fail(w, 409, "请先在网站设置中解除「"+boundSite+"」的应用代理绑定")
			return
		}
		var out DockerJobResult
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/projects/jobs", op, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.compose.delete", in.ConfirmName, "queued")
		send(w, 202, out)
	}))
	m.HandleFunc("POST /api/docker/networks", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Name     string `json:"name"`
			Internal bool   `json:"internal"`
		}
		if !decode(w, r, &in) {
			return
		}
		if !validDockerResourceName(in.Name) {
			fail(w, 400, "Docker 网络名称无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/networks", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.network.create", in.Name, "success")
		send(w, 201, out)
	}))
	m.HandleFunc("DELETE /api/docker/networks/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		id := r.PathValue("id")
		if !decode(w, r, &in) {
			return
		}
		if !validDockerObjectID(id) || !validDockerResourceName(in.ConfirmName) {
			fail(w, 409, "请输入网络名称确认删除")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/docker/networks/"+id, map[string]string{"expected_name": in.ConfirmName}, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.network.delete", in.ConfirmName, "success")
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/docker/volumes", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &in) {
			return
		}
		if !validDockerResourceName(in.Name) {
			fail(w, 400, "Docker 卷名称无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/volumes", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.volume.create", in.Name, "success")
		send(w, 201, out)
	}))
	m.HandleFunc("DELETE /api/docker/volumes/{name}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		name := r.PathValue("name")
		if !decode(w, r, &in) {
			return
		}
		if !validDockerResourceName(name) || in.ConfirmName != name {
			fail(w, 409, "请输入卷名称确认删除")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/docker/volumes/"+name, nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.volume.delete", name, "success")
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/docker/containers/{id}/logs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		if !validDockerObjectID(id) {
			fail(w, 400, "容器标识无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/containers/"+id+"/logs", nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/docker/jobs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in DockerJobRequest
		if !decode(w, r, &in) {
			return
		}
		in.JobID = ID()
		if e := ValidateDockerJob(in); e != nil {
			fail(w, 400, e.Error())
			return
		}
		var out DockerJobResult
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/jobs", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker."+in.Action, in.Image+":"+in.Name, "queued")
		send(w, 202, out)
	}))
	m.HandleFunc("GET /api/docker/jobs/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) {
			fail(w, 400, "Docker 作业标识无效")
			return
		}
		var out DockerJobResult
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/jobs/"+r.PathValue("id"), nil, &out); e != nil {
			fail(w, 404, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/docker/containers/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !validDockerObjectID(id) || (action != "start" && action != "stop" && action != "restart") {
			fail(w, 400, "容器操作无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/containers/"+id+"/"+action, map[string]any{}, &out); e != nil {
			_ = a.Store.Audit(u.Username, "docker.container."+action, id, "failed")
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.container."+action, id, "success")
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/docker/containers/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmID string `json:"confirm_id"`
		}
		id := r.PathValue("id")
		if !decode(w, r, &in) {
			return
		}
		if !validDockerObjectID(id) || in.ConfirmID != id[:12] {
			fail(w, 409, "请输入容器 ID 的前 12 位确认删除")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/docker/containers/"+id, nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.container.delete", id, "success")
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/docker/images/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmID string `json:"confirm_id"`
		}
		id := r.PathValue("id")
		if !decode(w, r, &in) {
			return
		}
		if !validDockerObjectID(id) || in.ConfirmID != id[:12] {
			fail(w, 409, "请输入镜像 ID 的前 12 位确认删除")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/docker/images/"+id, nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "docker.image.delete", id, "success")
		send(w, 200, out)
	}))
}
