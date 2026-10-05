# 云栈应用仓库

这是云栈面板的官方应用包仓库。面板只在用户点击安装时拉取指定版本的应用包，校验 SHA-256 后交给本地受限执行器。

## 安全边界

- 应用包不允许携带或执行任意 root Shell。
- `runtime` 只能引用面板已审核的固定版本运行时。
- `compose` 只能使用固定镜像、回环端口、命名卷和非特权容器。
- `panel-module` 只能激活面板已审核的功能标识和管理入口。
- 不支持的系统、CPU 架构、过期依赖或未接通处理器的应用不得标记为 `ready`。

## 仓库结构

- `registry/apps.json`：受审核的源注册表。
- `schema/app.schema.json`：应用清单 JSON Schema。
- `dist/catalog-v1.json`：面板拉取的精简目录。
- `dist/apps/<id>/<version>/`：应用包及 SHA-256。
- `tools/build.mjs`：以确定性 JSON 生成发布目录。
- `tools/verify.mjs`：校验清单、包哈希、ID 唯一性和安全约束。

## 本地验证

```bash
npm test
```

`dist/` 是发布产物，必须和源注册表一起提交，以便面板直接使用 GitHub Raw/CDN 拉取。

## 进度口径

- `ready`：处理器、安装/卸载/状态、健康探针与管理入口均已接通。
- `integration`：应用包已定义，正在接入面板处理器，不对用户显示“可安装”。
- `design`：功能边界已定义，尚未进入安装验收。

