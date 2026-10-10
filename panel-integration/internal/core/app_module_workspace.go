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
		return []AppModuleSection{section("network", "监听与连接", "对比 TCP / UDP 监听基线，区分公网和回环暴露；不把端口变化直接判定为入侵。", nil, []string{"run"}), section("baseline", "可信端口基线", "确认当前监听服务可信后保存；新基线替换旧基线，不修改防火墙和监听服务。", nil, []string{"baseline"}), section("ids-events", "被动 IDS 采集与告警", "只读取已显式准备、配置的独立采集引擎；打开页面不安装、不启用抓包。核对真实程序、账户、启动参数、已提交的规则选择与新鲜计数；旧计数、丢包和处理异常不宣称正常。不自动封禁；加密正文不能解密。", []string{"from_time", "to_time", "search", "severity", "limit", "offset"}, []string{"ids-report"}), section("ids-service", "IDS 采集服务", "显式准备或升级不启用采集；升级旧引擎前须停止采集并关闭开机采集。维护审核到期、版本不受支持或迁移待恢复时拒绝启动。引擎迁移恢复须先核对当前修订；提交任务不代表已完成，恢复后仍须单独启动。每个本机网段须包含接口真实地址。保存使用修订锁和独立两文件恢复；启停与开机选择分离，停用保留日志，不改变网卡、防火墙或网站。手动轮转仅重开已核对引擎的日志；最多保留 4 份、每份 8 MiB，超过窗口只退役完整摘要匹配的旧归档，保留近期退役摘要；不是永久审计存储。", []string{"network_interface", "home_networks", "prepare_ids", "expected_revision", "enabled"}, []string{"ids-prepare", "ids-config", "ids-start", "ids-stop", "ids-boot", "ids-recover", "ids-rotate"}), section("ids-rules", "规则数据与选择", "下载存放、原生校验、启用选择分开。先刷新实际报表，再选择完整验签且授权仍有效的数据。独立后台事务保留原配置、规则身份和运行选择；失败可显式恢复。网卡配置保留已选规则，不自动切换；重启核对所有原始签名和文件，过期的已提交数据保留并警告，不当成新的启用授权。", []string{"expected_revision"}, []string{"ids-rules"})}
	case "website-statistics-v2":
		return []AppModuleSection{section("statistics", "持久化访问历史", "查询增量保存的实际访问日志、请求总耗时分位数与分布。先核对历史范围、积压、退役与异常来源；后台采集不依赖页面打开，查询参数和原始 User-Agent 不进入历史数据库。慢请求阈值只改变慢请求明细，不筛除其他有效请求。", []string{"site_id", "from_time", "to_time", "search", "status_code", "min_seconds", "only_bots"}, []string{"run"})}
	case "website-analytics":
		return []AppModuleSection{section("statistics", "访问统计", "按网站、时间、路径、状态码和慢请求筛选实际访问日志。", []string{"site_id", "from_time", "to_time", "search", "status_code", "min_seconds", "only_bots"}, []string{"run"})}
	case "files-sync":
		return []AppModuleSection{
			section("sync", "本机手动同步", "先预览差异，再执行增量复制。不会删除目标文件；冲突保留并报告。", []string{"site_id", "target_site_id", "target_project_id", "excludes"}, []string{"preview", "sync"}),
			section("plans", "本机实时与定时同步", "可开启 Linux 文件事件驱动增量复制，保留定时补查；初次启用会立即补同步。关闭浏览器不影响计划；暂停后不再自动写入，排除缓存与动态目录，不能形成同步环。", []string{"resource_id", "site_id", "target_site_id", "excludes", "interval", "realtime", "enabled", "expected_revision"}, []string{"run", "schedule", "run-plan", "pause-plan", "resume-plan", "remove-plan"}),
			section("remote-target", "跨服务器 SFTP 连接", "先在可信 Linux/OpenSSH 服务器设置受限非 root SFTP 账户。填写固定 IP 与已独立核实的 SSH 主机公钥；不接受域名、自动信任或远端命令。目标和私有备份目录必须预先存在、同一文件系统并由该非 root 用户拥有；备份目录必须 0700，且位于公开目标之外。已有目标身份不可改写，新目标使用新标识；留空认证材料保留原凭据。连接检测只读。", []string{"remote_target_id", "remote_target", "password", "remote_private_key", "enabled", "expected_revision"}, []string{"remote-targets", "save-remote", "probe-remote"}),
			section("remote-transfer", "跨服务器增量复制", "先从连接列表选择远端，再选择源网站、预览冲突和提交后台任务。每个远端连接固定一个来源；最多 10000 文件、256 MiB，单文件 8 MiB、120 秒；远端改变的文件保留，受管旧版本留在私有目录。更新有短暂路径交接，不保证零停机。实时与定时策略独立管理，手动提交不改变计划。关闭浏览器不影响已排队任务；提交回执丢失时保留原任务标识，刷新任务列表核对，不盲目换键重发。", []string{"remote_target_id", "site_id", "excludes", "expected_revision", "remote_request_id"}, []string{"remote-preview", "queue-remote"}),
			section("remote-plans", "跨服务器实时与定时同步", "先选连接与来源、预览冲突，填写独立计划标识；连接修订号和计划修订号独立。显式保存启用后按 60–86400 秒间隔补查，完整成功后才安排下一次；错过多次只合并一次，不重叠运行。接受中断、原任务丢失、冲突、凭据改变或存储异常安全暂停，保留原任务标识；核对并恢复原交接后，先只读核对当前连接修订号，再显式重新启用。暂停停止后续交接但已完成文件和备份保留；移除保留计划身份与证据。最多 16 个保留计划记录，每个连接一个未移除计划。可显式开启 Linux 内核文件事件；0.5–2 秒合并变化，持久保存变化序号，由原有 5 秒后台任务队列接收。不重叠、不把执行中的新变化误判为已同步。首次监听、动态目录和重启完整补查；监听失败、超限或溢出显示降级，仍按间隔补查。不会自动删除满额任务或备份，满额安全暂停。", []string{"resource_id", "remote_target_id", "remote_target_revision", "site_id", "excludes", "interval", "realtime", "enabled", "expected_revision"}, []string{"remote-plans", "schedule-remote-plan", "pause-remote-plan", "resume-remote-plan", "remove-remote-plan"}),
			section("remote-jobs", "远端任务与恢复", "刷新持久任务后点击记录，读取详情、请求取消或恢复中断交接。取消停止后续文件交接，不删除已完成文件或备份；只有明确可验证的旧文件或已发布新文件才能恢复，遇到外部改动拒绝覆盖。执行器重启时运行任务安全暂停，剩余文件不自动重传。最多 128 个任务、512 份远端事务及 256 MiB 备份，不自动删除证据。", []string{"remote_request_id", "remote_target_id"}, []string{"remote-jobs", "remote-job", "cancel-remote", "recover-remote"}),
			section("remote-archive", "远端任务私有归档", "先选择可验证已结束的任务；按完整记录摘要和 ARCHIVE REMOTE 任务标识确认后，只移动本机任务记录，不删除远端内容、备份或检查点。执行中、中断、检查点异常或待恢复交接拒绝归档；归档后原标识仍可查询和重放，不会重新执行同步。最多 2048 份或 16 MiB，满额停止新归档。点击归档表记录后可读取原任务；不提供证据永久删除。", []string{"remote_request_id", "expected_sha", "confirm", "limit", "offset"}, []string{"remote-archive", "archive-remote-job"}),
			section("remote-backups", "远端备份与容量", "只读核对实际 0700 私有事务目录、暂存和原文件备份，不返回内容或认证材料。正好满额仍可查询；活动事务最多 512 份、256 MiB，每次交接保留 16 MiB。未知条目、异主或链接拒绝不完整统计。它不是磁盘硬配额，外部写入仍可能改变库存。选择记录可独立核对完整摘要；不会自动归档或删除。", []string{"remote_target_id", "expected_revision", "limit", "offset"}, []string{"remote-backups"}),
			section("remote-backup-maintenance", "受控远端备份归档", "先暂停该连接计划、核对已结束任务与文件交接，再从实际库存选择原事务并核对完整摘要。填写 ARCHIVE BACKUP 原事务标识，仅迁移到固定私有归档，保留所有字节、权限和原身份；不改公开目标、同步任务或检查点，不删除备份。未完成操作保留原摘要，填写 RECOVER BACKUP 原事务标识显式核对恢复；禁止重新提交或换身份。满额、损坏、异主、未知条目或内容改变拒绝迁移。仅可信协作非 root Linux/OpenSSH、同文件系统；不是内核条件式无覆盖，也不是独立不可变快照。", []string{"remote_target_id", "expected_revision", "resource_id", "expected_sha", "confirm"}, []string{"remote-backup-preview", "archive-remote-backup", "recover-remote-backup"}),
			section("remote-backup-store", "远端保留归档库存", "只读核对全部实际容器和分页元数据，每连接最多 512 份、1 GiB 逻辑字节，未知或缺失记录拒绝不完整统计。此清单不重新读取完整文件内容；选择原记录再核对或显式恢复。硬链接可能随公开目标的外部写入改变，不是独立不可变快照。不会自动清理，满额须另行备份维护。", []string{"remote_target_id", "expected_revision", "limit", "offset"}, []string{"remote-backup-archive"}),
		}
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
		return []AppModuleSection{section("entries", "入口与检查报告", "读取实际受管配置、持续 HTTP 检查状态及最近 32 次状态转换。未检查为 unknown，超过两倍间隔加超时时间为 stale，不以 TCP 建连冒充应用健康。单击入口记录进入修改；最多 64 个活动入口。", nil, []string{"run"}), section("entry", "入口与节点", "独立回环 HTTP 入口、权重、备用节点和 IP 粘滞。后端默认 HTTP；显式 HTTPS 转发使用固定 IP、指定后端 SNI/Host 名称、有效证书链与入口专用公共 CA，最低 TLS 1.2。不跳过验证、不失败降级、不安装全局信任；最多 4 个 CA / 16 KiB。保存核对修订号，持久化原配置后校验并重载；旧进程监听交接与新入口指纹验证后提交。HTTP/HTTPS 就绪检查可选；检查与业务转发独立；HTTP 后端的 HTTPS 检查须用独立就绪端口，TLS 后端允许同端口检查，并验证入口域名、有效期及系统信任库或显式公共 CA（不修改全局信任、不跳过验证）。最多 8 个入口、合计 32 个节点，全局并发 4；浏览器关闭后仍检查，停用后不启动后续检查，进行中的请求按超时结束。", []string{"domain", "port", "nodes", "sticky", "backend_tls", "health_check", "confirm", "expected_revision"}, []string{"save"}), section("health", "探测与移除", "TCP 探测仅验证建连；应用检查使用固定节点 IP、域名 Host、GET 相对路径、指定 2xx 状态及可选内容，拒绝跳转，响应最多 16 KiB。连续失败/成功达到阈值才变更状态。默认只观测。v1.7.0 可显式启用自动流量并精确确认；阈值判定后由三/四文件事务、原生重载与入口指纹核对摘除或恢复，不默认为旧策略开启。初始未知可转发，全部失败全部摘除；旧长请求不中断。移除只移除入口，永久修订号与检查记录保留，不删除网站或节点数据。", []string{"domain", "expected_revision"}, []string{"probe", "check-http", "remove"}), section("recovery", "中断恢复", "只恢复可信事务里的原配置。历史 HTTP 两文件、TLS 三文件（含专用 CA），自动流量三文件或 TLS 四文件（另含完整检查记录）须逐份匹配完整旧版或新版；外部修改、损坏备份或未知状态保留并拒绝覆盖。中断事务暂停持续检查；修订号改变后旧检查结果失效。最多 512 份配置事务，不自动清除证据。", nil, []string{"recover"})}
	case "mobile-pwa":
		return []AppModuleSection{section("mobile", "Android / iOS 客户端", "下载 Android APK、iOS 源码与未签名设备构建。原生地址校验、TLS 和后台锁屏保护会话；业务操作继续使用真实面板与原权限。正式包要求 HTTPS。", nil, []string{"run"})}
	case "apache-waf":
		return []AppModuleSection{section("apache", "防护与原生校验", "读取 Apache 防护规则和真实配置检查结果；规则覆盖恶意方法、扫描器、路径穿越和常见查询攻击。", nil, []string{"run"})}
	case "php-code-security":
		return []AppModuleSection{
			section("scan", "PHP 风险扫描", "静态扫描不会执行或修改 PHP。支持排除路径、规则和风险级别筛选；命中不等于已确认后门。选择命中项进入受控隔离。", []string{"site_id", "excludes", "search", "severity"}, []string{"run"}),
			section("quarantine", "受控代码隔离", "人工审查后填写 QUARANTINE 相对文件路径。再次核对摘要，普通单链接 PHP/PHTML/INC 文件原子移出公开目录，独立私有备份保留。拒绝链接、特殊权限、跨文件系统和超过 8 MiB 文件；不自动终止已有请求或清除 OPcache，其他程序仍能重新创建路径。", []string{"site_id", "path", "expected_sha", "confirm"}, []string{"quarantine"}),
			section("quarantine-list", "隔离箱与备份验证", "分页查看实际事务、备份摘要与原位置存在状态。最多 512 条记录、256 MiB 原始备份预算；不自动删除隔离内容。选择记录进入无覆盖恢复。", []string{"site_id", "search", "limit", "offset"}, []string{"quarantine-list"}),
			section("quarantine-restore", "无覆盖恢复与事务修复", "恢复填写 RESTORE PHP 记录标识；中断事务填写 RECOVER PHP 记录标识。核对网站、父目录、原摘要和修订号，恢复原内容、权限、所有者及扩展属性。原位置已有新文件或备份损坏时拒绝覆盖；备份和执行历史保留。仍有隔离或中断事务时不允许卸载应用或归档网站。", []string{"site_id", "resource_id", "path", "expected_sha", "expected_revision", "confirm"}, []string{"restore-quarantine", "recover-quarantine"}),
		}
	case "task-manager":
		return []AppModuleSection{section("processes", "实时进程", "读取 CPU、内存、IO 和进程启动身份。单击受管进程进入终止操作。", nil, []string{"run"}), section("terminate", "受控终止", "仅对非 root 云栈受管进程发送 SIGTERM，并再次核对 PID 启动序号。", []string{"pid", "start_time"}, []string{"terminate"})}
	case "user-manager":
		return []AppModuleSection{section("users", "账户列表", "查看角色、网站范围、菜单授权、双重验证和有效会话数。", nil, []string{"run"}), section("account", "账户与授权", "独立菜单限制与后端校验同时生效，不扩大原角色与网站范围。更新权限立即撤销旧会话，使用当前修订号防止覆盖。", []string{"username", "password", "role", "site_ids", "menu_ids", "expected_revision"}, []string{"create", "update"}), section("sessions", "会话与删除", "不允许删除当前用户、最后一个完整权限管理员或管理权限高于自身的账户。", []string{"username", "expected_revision"}, []string{"revoke", "delete"})}
	case "disk-analysis":
		return []AppModuleSection{section("disk", "目录空间分析", "查看目录、扩展名和大文件分布；单击目录下钻。只读，不删除文件，不跟随符号链接。", []string{"site_id", "path"}, []string{"run"})}
	case "platform-ops":
		return []AppModuleSection{section("hosts", "主机健康", "读取已登记主机的只读健康数据；验证 HTTPS 证书，不支持远程命令。", nil, []string{"run"}), section("host", "登记主机", "只读令牌加密保存。移除仅删除主机登记，不操作远端软件。", []string{"resource_id", "url", "token"}, []string{"add", "remove"}), section("tokens", "本机只读授权", "令牌只在生成时显示一次；输入要撤销的令牌，撤销立即生效。", []string{"token"}, []string{"issue-token", "revoke-token"})}
	case "nfs-manager":
		return []AppModuleSection{
			section("server", "共享服务状态", "独立 NFSv4 用户态服务，只导出受管网站目录。AUTH_SYS 不加密，仅用于可信网络或 VPN；不修改防火墙、系统 NFS 配置或 RPC 映射。启停保留网站文件。", nil, []string{"server-report", "server-probe", "server-start", "server-stop", "server-recover"}),
			section("listener", "NFSv4 监听配置", "默认 127.0.0.1:2049。非回环必须填写 EXPOSE NFS IP:端口（IPv6 使用方括号）。保存核对修订号；活动服务重启并检查真实 NFS RPC，失败恢复旧配置，停止状态不会自动启动。切换中断现有连接，客户端可能等待约 30 秒的协议恢复期。", []string{"bind_address", "port", "expected_revision", "confirm"}, []string{"server-config"}),
			section("export", "网站目录导出", "选择普通网站目录，留空为网站根。客户端必须为明确 IP/CIDR，禁止 DNS 和 /0。所有客户端（包括 root）映射为该网站 UID/GID。默认只读，可写需填写 SHARE RW 导出名称；不跟随链接切换导出目录。", []string{"resource_id", "site_id", "path", "client_allow", "read_only", "expected_revision", "confirm"}, []string{"export-save"}),
			section("export-remove", "移除共享导出", "从共享列表选择导出。移除不删除网站文件；移除最后一个导出前必须先停止服务。已有导出禁止静默切换目录，需先移除再重新登记。", []string{"resource_id", "expected_revision"}, []string{"export-remove"}),
			section("mounts", "客户端挂载列表", "核对内核真实挂载、来源、端口与安全选项，不以 systemd 状态代替挂载存在。", nil, []string{"run"}), section("mount", "远程共享挂载", "最多 64 个挂载。默认只读，强制 nosuid / nodev / noexec / TCP 与 hard；来源支持 IP:/导出名称、域名:/路径及 [IPv6]:/路径。填写远程端口（默认 2049），持久化配置，重启后可恢复。服务失联时 hard 挂载会等待恢复而非返回不完整写入；不会接管未登记的外部挂载。", []string{"resource_id", "source", "port", "read_only"}, []string{"mount"}), section("unmount", "安全取消挂载", "仅取消指定受管挂载；使用中保留记录并报错，释放使用后可重试；不使用强制或延迟卸载。", []string{"resource_id"}, []string{"unmount"}),
		}
	case "pm2-manager":
		return []AppModuleSection{section("apps", "应用状态", "读取真实 systemd / PM2 状态，以网站独立用户运行；环境变量只展示名称，不返回密钥值。", nil, []string{"run"}), section("create", "部署 Node 应用", "选择站点内 JS 入口和回环端口；支持 1–8 个 PM2 进程，所有进程的内存重启阈值总计不超过 1 GiB。环境变量可用 JSON 增量写入。", []string{"site_id", "resource_id", "entry", "port", "instances", "memory_mb", "environment_patch"}, []string{"create"}), section("control", "服务与日志", "修改入口、端口、进程数、内存阈值及环境变量会校验修订号并重启；失败恢复旧配置。变量框留空保留全部现有值，值为 null 删除指定变量。删除受管服务保留网站源文件。", []string{"resource_id", "entry", "port", "instances", "memory_mb", "environment_patch", "expected_revision"}, []string{"update", "start", "stop", "restart", "logs", "delete"}), section("dependencies", "锁定依赖部署", "网站根目录准备 package.json 和 v2/v3 package-lock.json，选择项目后安装。只接受公共 npm HTTPS 包及 SHA-512 摘要，拒绝自定义源、本地链接。默认禁止安装脚本；显式开启时仅以该网站用户运行，用于原生扩展和构建，不传入应用环境秘密。独立后台安装期间保留线上服务，切换失败恢复旧依赖。中断可取消并恢复；归档仅移动已完成旧记录，不删除依赖备份。", []string{"resource_id", "expected_revision", "allow_install_scripts"}, []string{"dependencies", "deployment", "cancel-deployment", "recover-deployment", "archive-deployments"})}
	case "pure-ftpd":
		return []AppModuleSection{
			section("ftp", "服务与账户", "读取真实服务、证书、配置与账户；启停不删除文件。账户与配置提交均有 root 私有恢复记录。", nil, []string{"run", "probe", "start", "stop", "recover-service"}),
			section("listener", "监听与域名证书", "保存使用当前修订号；活跃服务先切换再探测真实 TLS，失败恢复原配置与证书。非回环地址须填写 EXPOSE FTPS IP:端口，并选择系统信任且覆盖 FTP 域名的证书。不会修改防火墙、安全组或路由。配置切换会中断现有连接。", []string{"bind_address", "port", "passive_start", "passive_end", "passive_address", "certificate_id", "domain", "max_clients", "max_per_ip", "idle_minutes", "expected_revision", "confirm"}, []string{"service-config"}),
			section("account", "网站 FTP 账户", "用户 chroot 到网站目录，控制和数据通道强制 TLS；密码仅写入、不回显、不进入命令参数或历史。变更权限仅用于后续新连接，不强行终止既有会话。", []string{"site_id", "username", "password"}, []string{"create", "password"}),
			section("account-limits", "账户限制", "从服务与账户列表选择账户后保存。带宽、客户端 IPv4/CIDR 和会话限制由 Pure-FTPd 对新连接执行。容量及文件数量是 FTP 软配额，不是内核硬配额：同网站账户共享目录计数，网站程序或其他通道写入后应停止 FTP 并重新统计。首次启用配额前必须先统计。0 为不限；空允许清单为全部，拒绝优先。", []string{"username", "quota_mb", "quota_files", "upload_kb", "download_kb", "max_sessions", "client_allow", "client_deny", "expected_sha"}, []string{"account-limits"}),
			section("quota", "容量重统计", "先停止 FTP，再从列表选择账户并重统计；不会自动断开连接或重新启动。扫描当前网站的常规文件及目录，不跟随链接、不跨挂载点，遇到硬链接、特殊文件或超限拒绝不完整结果。上限 100000 项、64 层、20 秒；应用仍可能并发写入，所以结果不是磁盘硬配额。保留旧计数备份。", []string{"username", "expected_sha"}, []string{"recount-quota"}),
			section("delete", "移除账户", "只删除指定虚拟账户，保留网站目录和文件；已有会话需主动停止服务才会中断。", []string{"username"}, []string{"delete"}),
		}
	}
	return nil
}
