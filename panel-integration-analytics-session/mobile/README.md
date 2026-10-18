# 云栈原生移动客户端

原生 Android Activity / iOS SwiftUI + WKWebView 连接用户自己的云栈面板，业务页面来自已安装面板，不是离线模拟数据。原生层负责地址验证、TLS、后台锁屏、设备认证、会话清除和文件选择；业务操作继续使用面板的 HttpOnly Cookie、CSRF、TOTP、角色和网站范围。不使用 JavaScript 原生桥，不保存账号密码，不将管理会话交给外部浏览器或系统下载器。

正式构建只接受 HTTPS；安全入口路径可以随地址填写，但不能带临时令牌、查询参数或 URL 用户名密码。不能忽略证书错误。QA 构建只放行模拟器或 adb 回环 HTTP，不能分发为正式包。手机的 `127.0.0.1` 指手机自身，不是电脑；连接实际服务器需要该服务器可达的 HTTPS 面板地址或安全隧道。

Android 最低 API 30（Android 11），构建使用 JDK 17、Gradle 8.13、Android Gradle Plugin 8.13.2、SDK 36：

```sh
cd android
gradle test assembleRelease lint
```

生成的 `app-release-unsigned.apk` 须由发布者使用独立保管的稳定私钥签名后安装。签名密码和私钥不放入源码、APK、CI 日志或面板安装包；使用 `apksigner sign --ks ... --ks-pass file:...` 并再执行 `apksigner verify`。仓库没有任何生产签名密钥。

iOS 最低 18.4：

```sh
cd ios
swift test
xcodebuild -project YunzhanMobile.xcodeproj -scheme YunzhanMobile \
  -configuration Release -destination generic/platform=iOS \
  -derivedDataPath /tmp/yunzhan-ios-build CODE_SIGNING_ALLOWED=NO build
```

未签名 `.app` 是 arm64 设备构建，不是可直接安装或上架的 IPA。安装到 iPhone 需要用户自己的合法开发者签名。源码可在 Xcode 打开后签名。地址单元测试检查精确来源、端口、降级协议、账号令牌和异常 URL；会话状态测试另外检查文件选择、设备认证、后台锁定及旧连接回调隔离。

1.3.1 的文件选择回调绑定原连接及一次性选择凭据；Android Activity 的请求码在该实例内不复用，iOS 另外核对原选择器实例。后台返回的所选文件仅保留在当前进程内，锁定期间不会交给网页上传；通过设备认证并回到前台后才提交。取消、断开、换连接或销毁会话会撤销凭据并丢弃待提交选择。旧认证成功回调不能解锁新连接。iOS 的系统认证短暂 inactive 与真正 background 区分处理，真正进入后台会撤销认证；这些状态测试不代替真机生物识别和文件提供者验收。

边界：业务页使用当前面板的响应式 UI，不是独立重写的所有原生业务表单；无离线管理、系统推送和自动后台运维。管理文件下载暂由可信浏览器登录后完成；移动端不自动导出敏感管理会话。Android 使用 FLAG_SECURE 隐藏截图和最近任务；iOS 遮挡后台快照，但不能承诺阻止系统截图。清除会话删除本地凭据，不替代服务器管理员的会话撤销。设备未设锁屏时，返回已锁定会话需要退出重登或先设置系统锁屏。以上边界不能标记为商业移动端全能力完成。
