# 云栈原生移动客户端

原生 Android Activity / iOS SwiftUI + WKWebView 连接用户自己的云栈面板，业务页面来自已安装面板，不是离线模拟数据。原生层负责地址验证、TLS、后台锁屏、设备认证、会话清除和文件选择；业务操作继续使用面板的 HttpOnly Cookie、CSRF、TOTP、角色和网站范围。不使用 JavaScript 原生桥，不保存账号密码，不将管理会话交给外部浏览器或系统下载器。

正式构建只接受 HTTPS；安全入口路径可以随地址填写，但不能带临时令牌、查询参数或 URL 用户名密码。不能忽略证书错误。QA 构建只放行模拟器或 adb 回环 HTTP，不能分发为正式包。手机的 `127.0.0.1` 指手机自身，不是电脑；连接实际服务器需要该服务器可达的 HTTPS 面板地址或安全隧道。

Android 最低 API 30（Android 11），构建使用 JDK 17、Gradle 9.3.1、Android Gradle Plugin 9.1.1、SDK 37.0，目标 API 37：

Android 模块是纯 Java，使用模块级 `enableKotlin = false` 避免自动加入无用的 Kotlin 运行库；仍保留现代构建 DSL、Debug/Release 两套单元测试及严格 lint。

```sh
cd android
gradle testDebugUnitTest testReleaseUnitTest assembleRelease lintDebug lintRelease
```

生成的 `app-release-unsigned.apk` 须由发布者使用独立保管的稳定私钥签名后安装。签名密码和私钥不放入源码、APK、CI 日志或面板安装包；使用 `apksigner sign --ks ... --ks-pass file:...` 并再执行 `apksigner verify`。仓库没有任何生产签名密钥。

Android 17 的目标 API 37 要求局域网访问授权。仅在 Android 17+ 显示可选的原生「本地网络权限」按钮，由用户点击后交给系统授权；公网面板不要求这项授权。授权结束不会自动连接、重新加载或上传文件，也没有能够操作新会话的授权结果回调。拒绝授权不会降低 HTTPS、证书或来源检查。连接局域网服务器前请先授权，再手动连接；权限由系统设置撤销。这不代表已完成 Android 17 真机权限弹窗验收。

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

1.3.2 为 Android 与 iOS 的网页事件增加原 WebView 与连接凭据绑定。旧连接的进度、网络错误、弹窗、文件选择及下载回调不能操作新连接；网页确认弹窗使用一次性凭据，进入后台、断开、销毁或更换连接时撤销，确认按钮在点击时再次核对归属。网页进程退出后清除本地登录状态，不自动恢复旧页面或会话。Android 原生界面文本使用中英文资源，Debug 与 Release lint 均将警告视为失败。iOS 保留系统真实设备 User-Agent 并附加客户端版本，不再伪装固定 iPhone/iOS 版本。

锁定时不仅绘制遮罩：Android 将 WebView 设为不可见并从辅助功能树隐藏其后代；iOS 在同一次隐私状态同步中隐藏原生 WKWebView 及其辅助功能元素，并同步 SwiftUI 辅助功能隐藏。断开时立即隐藏旧原生视图。恢复必须在原连接的一次性认证成功、当前会话已解锁且回到前台后进行。文件选择返回不自动恢复网页。两个平台都需要各自的真实平台交互验收，Android 模拟器结果不能代替 iOS VoiceOver 或真机验收。

面板是需要 JavaScript 的 Vue 业务页面。Android 仅在固定 WebSettings 配置方法中确认这一条必需的 lint 提示，不全局关闭安全检查；正式包仍要求 HTTPS、证书错误取消连接，不提供 JavaScript/原生桥，禁用文件和 content URL 访问、混合内容及第三方 Cookie。面板服务端必须继续发送自身的严格 CSP（包括 `default-src 'self'`、`script-src 'self'` 和 `connect-src 'self'`），不能加载不受信任的外站脚本。Android 官方明确说明，资源回调只收到重定向的初始 URL，且不覆盖 `blob:` 和 `javascript:`；因此原生回调不能被表述为覆盖全部流量的网络防火墙。参见 [WebViewClient 资源回调](https://developer.android.com/reference/android/webkit/WebViewClient) 和 [WebView 原生桥安全指南](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges)。

边界：业务页使用当前面板的响应式 UI，不是独立重写的所有原生业务表单；无离线管理、系统推送和自动后台运维。管理文件下载暂由可信浏览器登录后完成；移动端不自动导出敏感管理会话。Android 使用 FLAG_SECURE 隐藏截图和最近任务；iOS 遮挡后台快照，但不能承诺阻止系统截图。清除会话删除本地凭据，不替代服务器管理员的会话撤销。设备未设锁屏时，返回已锁定会话需要退出重登或先设置系统锁屏。以上边界不能标记为商业移动端全能力完成。
