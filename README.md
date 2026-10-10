# 云栈应用仓库

供云栈面板按需拉取应用目录、应用包及签名文件。

`dist/catalog-v1.json` 为应用目录，`dist/apps/` 保存版本化应用包，`signatures/` 保存目录签名与公钥。面板验证 Ed25519 签名和 SHA-256 后安装。

面板适配 Debian 12/13、Ubuntu 22.04/24.04/26.04，以及 x86_64、ARM64。商店会判断本机兼容性；具体应用以签名清单中的系统与架构限制为准。

12 个停止维护的 PHP 版本仅用于 x86_64 隔离兼容环境，不在 ARM64 上强制模拟运行。

`panel-integration/source-sha256.json` 校验当前可审查源码，`release-source-inputs.json` 保留已发布包的冻结输入及原始哈希。发布后的 Go 测试修正通过 `test_overrides` 记录原始摘要和原因，仅允许 `cmd/`、`internal/` 下的 `_test.go` 文件；生产源码仍必须与冻结输入完全一致。测试修正不表示发布二进制已重建或线上服务已验证。
