package core

// Workspaces describe real operations exposed by the fixed module handlers.
// They are also used by the client to send only the active workflow's fields.
type AppModuleSection struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	Help    string   `json:"help"`
	Fields  []string `json:"fields"`
	Actions []string `json:"actions"`
}

func ModuleWorkspace(id string) []AppModuleSection {
	section := func(id, label, help string, fields, actions []string) AppModuleSection {
		return AppModuleSection{id, label, help, fields, actions}
	}
	site := []string{"site_id"}
	integrity := []string{"site_id", "excludes", "interval", "realtime"}
	switch id {
	case "site-diagnosis":
		return []AppModuleSection{section("diagnose", "网站健康诊断", "检查真实 DNS、站点 HTTP、TLS、Nginx 配置和文件状态；失败项会提供处置建议。", site, []string{"run"})}
	case "network-threat-detection":
		return []AppModuleSection{section("network", "监听与连接", "对比 TCP / UDP 监听基线，区分公网和回环暴露；不把端口变化直接判定为入侵。", nil, []string{"run"}), section("baseline", "可信端口基线", "确认当前监听服务可信后保存；新基线替换旧基线，不修改防火墙和监听服务。", nil, []string{"baseline"})}
	case "website-analytics", "website-statistics-v2":
		return []AppModuleSection{section("statistics", "访问统计", "按网站、时间、路径、状态码和慢请求筛选实际访问日志。", []string{"site_id", "from_time", "to_time", "search", "status_code", "min_seconds", "only_bots"}, []string{"run"})}
	case "files-sync":
		return []AppModuleSection{section("sync", "手动同步", "先预览差异，再执行增量复制。不会删除目标文件；冲突保留并报告。", []string{"site_id", "target_site_id", "target_project_id", "excludes"}, []string{"preview", "sync"}), section("plans", "实时与定时同步", "可开启 Linux 文件事件驱动增量复制，保留定时补查；初次启用会立即补同步。关闭浏览器不影响计划；暂停后不再自动写入，排除缓存与动态目录，不能形成同步环。", []string{"resource_id", "site_id", "target_site_id", "excludes", "interval", "realtime", "enabled", "expected_revision"}, []string{"run", "schedule", "run-plan", "pause-plan", "resume-plan", "remove-plan"})}
	case "daily-report":
		return []AppModuleSection{section("daily", "生成今日报告", "汇总资源、网站、任务、安全与证书到期情况；每日报告保存在面板数据库。", nil, []string{"run"}), section("archive", "历史日报", "选择历史日期读取已保存的报告，不会重新执行检查或覆盖旧日报。", []string{"resource_id"}, []string{"archive", "report"})}
	case "enterprise-tamper-proof", "website-tamper-proof", "file-monitor":
		fields := append([]string{}, integrity...)
		if id == "enterprise-tamper-proof" {
			fields = append(fields, "auto_restore")
		}
		sections := []AppModuleSection{section("policies", "监控策略", "查看实际监听状态；暂停立即停止后续自动检查与恢复，保留基线、备份和历史。", []string{"site_id", "expected_revision"}, []string{"policies", "pause", "resume"}), section("watch", "实时监控", "先选择策略，再切换实时模式和补查间隔。不重新建立基线；监听超限、失败或队列溢出会显示降级，定时补查仍保留。", []string{"site_id", "realtime", "interval", "expected_revision"}, []string{"watch-mode"}), section("baseline", "基线与检查", "建立基线前确认目录可信。排除缓存和动态目录；扫描超限会明确标记不完整。", fields, []string{"baseline", "check"})}
		if id != "file-monitor" {
			sections = append(sections, section("restore", "受控文件恢复", "从变更报告选择文件，校验当前摘要后恢复已备份内容。不会自动删除新增文件。", []string{"site_id", "path", "expected_sha"}, []string{"restore"}))
		}
		return sections
	case "load-balance":
		return []AppModuleSection{section("entry", "入口与节点", "管理独立回环 HTTP 入口、权重、备用节点和 IP 粘滞；保存先校验 Nginx，失败恢复原配置。", []string{"domain", "port", "nodes", "sticky"}, []string{"save"}), section("health", "健康与移除", "健康检测读取实际节点响应；移除仅删除指定受管入口。", []string{"domain", "port", "nodes"}, []string{"probe", "remove"})}
	case "mobile-pwa":
		return []AppModuleSection{section("mobile", "Android / iOS 客户端", "下载 Android APK、iOS 源码与未签名设备构建。原生地址校验、TLS 和后台锁屏保护会话；业务操作继续使用真实面板与原权限。正式包要求 HTTPS。", nil, []string{"run"})}
	case "apache-waf":
		return []AppModuleSection{section("apache", "防护与原生校验", "读取 Apache 防护规则和真实配置检查结果；规则覆盖恶意方法、扫描器、路径穿越和常见查询攻击。", nil, []string{"run"})}
	case "php-code-security":
		return []AppModuleSection{section("scan", "PHP 风险扫描", "静态扫描不会执行或修改 PHP。支持排除路径、规则和风险级别筛选；命中不等于已确认后门。", []string{"site_id", "excludes", "search", "severity"}, []string{"run"})}
	case "task-manager":
		return []AppModuleSection{section("processes", "实时进程", "读取 CPU、内存、IO 和进程启动身份。单击受管进程进入终止操作。", nil, []string{"run"}), section("terminate", "受控终止", "仅对非 root 云栈受管进程发送 SIGTERM，并再次核对 PID 启动序号。", []string{"pid", "start_time"}, []string{"terminate"})}
	case "user-manager":
		return []AppModuleSection{section("users", "账户列表", "查看角色、网站范围、双重验证和有效会话数。", nil, []string{"run"}), section("account", "账户与授权", "管理员拥有完整权限；操作员和只读用户受指定网站范围限制。更新权限立即撤销旧会话。", []string{"username", "password", "role", "site_ids"}, []string{"create", "update"}), section("sessions", "会话与删除", "撤销会话会要求重新登录；不允许删除当前用户或最后一个管理员。", []string{"username"}, []string{"revoke", "delete"})}
	case "disk-analysis":
		return []AppModuleSection{section("disk", "目录空间分析", "查看目录、扩展名和大文件分布；单击目录下钻。只读，不删除文件，不跟随符号链接。", []string{"site_id", "path"}, []string{"run"})}
	case "platform-ops":
		return []AppModuleSection{section("hosts", "主机健康", "读取已登记主机的只读健康数据；验证 HTTPS 证书，不支持远程命令。", nil, []string{"run"}), section("host", "登记主机", "只读令牌加密保存。移除仅删除主机登记，不操作远端软件。", []string{"resource_id", "url", "token"}, []string{"add", "remove"}), section("tokens", "本机只读授权", "令牌只在生成时显示一次；输入要撤销的令牌，撤销立即生效。", []string{"token"}, []string{"issue-token", "revoke-token"})}
	case "nfs-manager":
		return []AppModuleSection{section("mounts", "挂载列表", "读取真实挂载状态及受管清单。", nil, []string{"run"}), section("mount", "远程共享挂载", "默认只读，强制 nosuid / nodev / noexec；持久化受管配置，重启后可恢复。", []string{"resource_id", "source", "read_only"}, []string{"mount"}), section("unmount", "安全取消挂载", "仅取消指定受管挂载；使用中会报错，不使用强制或延迟卸载。", []string{"resource_id"}, []string{"unmount"})}
	case "pm2-manager":
		return []AppModuleSection{section("apps", "应用状态", "读取真实 systemd / PM2 状态，以网站独立用户运行，不使用 root 执行业务代码。", nil, []string{"run"}), section("create", "部署 Node 应用", "选择站点内 JS 入口和回环端口；支持 1–8 个 PM2 进程，所有进程的内存重启阈值总计不超过 1 GiB。", []string{"site_id", "resource_id", "entry", "port", "instances", "memory_mb"}, []string{"create"}), section("control", "服务与日志", "修改入口、端口、进程数和内存阈值会校验修订号并重启；失败恢复旧配置。删除受管服务保留网站源文件。", []string{"resource_id", "entry", "port", "instances", "memory_mb", "expected_revision"}, []string{"update", "start", "stop", "restart", "logs", "delete"})}
	case "pure-ftpd":
		return []AppModuleSection{section("ftp", "服务与账户", "读取实际服务、TLS 和虚拟账户；默认只监听回环地址，不自动开放公网端口。", nil, []string{"run"}), section("account", "网站 FTP 账户", "用户 chroot 到所选网站目录，强制 TLS；密码不进入命令参数和历史。", []string{"site_id", "username", "password"}, []string{"create", "password"}), section("delete", "移除账户", "只删除指定虚拟账户，保留网站目录和文件。", []string{"username"}, []string{"delete"})}
	}
	return nil
}
