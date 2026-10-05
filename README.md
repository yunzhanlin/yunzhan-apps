# 云栈应用仓库

这是云栈面板的应用包与可审阅实现仓库，覆盖 29 项部署应用、21 项专业运维功能。面板在安装时从 GitHub 拉取指定版本清单，验证 Ed25519 目录签名与 SHA-256，再交给本地受限执行器。软件本体的源码、二进制、系统包或镜像仅在需要时下载。

这是独立实现，不复制或解锁 aaPanel 的付费插件。功能验收以本文和清单列出的基础能力为准，不代表商业插件全部细节、攻防认证或生产 SLA。

## 安全边界

- 应用包不允许携带或执行任意 root Shell。
- `runtime` 只能引用面板已审核的固定版本运行时。
- `compose` 只能使用固定镜像、回环端口、命名卷和非特权容器。
- `panel-module` 只能激活面板已审核的功能标识和管理入口。
- 不支持的系统、CPU 架构或未接通处理器的应用不得标记为 `ready`。
- PHP 5.2–8.1 已停止维护，保持 `risk=eol`，不进入默认推荐列表；只允许固定摘要的隔离兼容环境，不能安装为主机 root PHP。PHP 后端使用内部网络；现代 Nginx 前端连接回环发布网络。它们并非安全生产运行时，建议尽快迁移到受维护版本。
- 文件同步不删除目标文件；未被检查点跟踪且不同内容的目标文件会报告冲突，不会自动覆盖。

## 仓库结构

- `registry/apps.json`：受审核的源注册表。
- `schema/app.schema.json`：应用清单 JSON Schema。
- `dist/catalog-v1.json`：面板拉取的精简目录。
- `dist/apps/<id>/<version>/`：应用包及 SHA-256。
- `tools/build.mjs`：以确定性 JSON 生成发布目录。
- `tools/verify.mjs`：校验清单、包哈希、ID 唯一性和安全约束。
- `panel-integration/`：实际 Go API、Linux 执行器、Vue 管理界面、systemd 单元、安装与验收脚本，附源文件 SHA-256 索引。
- `docs/functional-boundaries.md`：操作方法与功能边界。
- `docs/acceptance-50.json`：逐项基础功能验收证据摘要，不含凭据或客户数据。

## 本地验证

```bash
npm test
```

`dist/` 是发布产物，必须和源注册表一起提交，以便面板直接使用 GitHub Raw/CDN 拉取。

面板源码可在 `panel-integration/` 内用 `go test ./...`、`go build ./cmd/panel` 编译；Linux 执行器用 `GOOS=linux CGO_ENABLED=0 go build ./cmd/executor`。前端进入 `web/` 执行 `npm ci && npm run build`。实际部署必须安装配套 systemd 单元与配置，不能只替换浏览器页面。签名私钥不在仓库内。

配套 amd64 面板安装包通过 GitHub Releases 分发，附 `.manifest`、Ed25519 `.sig` 和 `.sha256`。先通过独立可信渠道确认公钥，再使用仓库中的 `packaging/signed-release.py` 在隔离 Debian 13 环境执行 `verify`、`install --preflight-only`、`install`；安装器会先备份已有数据库，失败时恢复旧版本。发布公钥 DER SHA-256：`8dfa7c2cca2a97434cdf74be88a0b5c0ec782d09e25540e4b50851b781229a2b`。当前是开发验收版本，不等同于生产安全认证；新模块只声明已经实测的 Debian 13 amd64。

## 进度口径

- `ready`：处理器、安装/卸载/状态、健康探针与管理入口均已接通。
- `integration`：应用包已定义，正在接入面板处理器，不对用户显示“可安装”。
- `design`：功能边界已定义，尚未进入安装验收。
