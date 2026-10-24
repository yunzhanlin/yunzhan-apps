package core

import "local/panel/internal/appcatalog"

const NativeMobileAppVersion = appcatalog.NativeMobileVersion

// Fixed, built-and-verified artifacts. Never accept download URLs from module
// settings. Private signing keys are not part of the panel or repository.
func NativeMobileDelivery() map[string]any {
	const release = "https://github.com/yunzhanlin/yunzhan-apps/releases/download/mobile-v1.3.2/"
	return map[string]any{
		"manifest": "/manifest.webmanifest", "installable": true,
		"version": NativeMobileAppVersion, "delivery_model": "原生安全容器 + 真实面板响应式业务页", "session_model": "HTTPS + HttpOnly + SameSite + CSRF + TOTP + 原角色与网站范围",
		"physical_device_acceptance": false, "android_target_sdk": 37, "native_source_inputs_sha256": "2b963086f95fdc30787c7d27ad5680b9fb5802e1dec28f5d824e3670f211a052",
		"android_emulator_session_acceptance": true, "android_emulator_api": 37, "ios_accessibility_ui_acceptance": false,
		"android_signer_sha256": "0ba923afca85db94f4bdabd6d235fcf1c7088bb167ace661bf21781d1c7f0bd5",
		"mobile_downloads": []map[string]string{
			{"name": "Android APK", "platform": "Android 11+ / 目标 API 37", "filename": "yunzhan-mobile-1.3.2-android.apk", "url": release + "yunzhan-mobile-1.3.2-android.apk", "sha256": "a76d4a9a04b4d46c35332b36e04590078a27e25885fd5abe6ede611be55b09e3", "state": "原发布者签名；正式包只连接 HTTPS；真机全流程尚未验收"},
			{"name": "iOS 未签名设备构建", "platform": "iOS 18.4+ / arm64", "filename": "yunzhan-mobile-1.3.2-ios-unsigned.tar.gz", "url": release + "yunzhan-mobile-1.3.2-ios-unsigned.tar.gz", "sha256": "ef86e336b7334bb29cad8570cc29eea0af0f9f26217b77bd914a94c429d4f365", "state": "需要自己的开发者签名；不是可直接安装的 IPA"},
			{"name": "Android + iOS 源码", "platform": "Gradle / Xcode", "filename": "yunzhan-mobile-1.3.2-source.tar.gz", "url": release + "yunzhan-mobile-1.3.2-source.tar.gz", "sha256": "6fcbbaa8d18ba1cb22aa050b849dd8d3e1488e8f845b32c1930cb0eea2cc313f", "state": "26 个源码文件、零覆盖；无生产私钥和账号密码"},
		},
		"scope": "原生可信 HTTPS、精确来源、后台锁屏、设备认证、一次性弹窗及文件选择回调隔离；网页进程退出清除本地会话。Android 17 局域网权限须由用户手动授予，不扫描或自动重连。Android 两变体各16项模型测试、严格 lint0，Swift16及iOS未签名arm64设备构建已验证。独立 Android17 模拟器已验证 WebView 隐私隐藏、系统 PIN 解锁、文档选择后锁定零提交与解锁后哈希一致、退出丢弃待提交文件、后台撤销确认及跨来源拒绝；正式 APK 保持原签名并拒绝明文 HTTP。模拟器不等于真机、生物识别、外部文件提供者或 iOS VoiceOver 验收；iOS 原生视图隐私隐藏已编译但未完成平台 UI 验收。业务页来自实际面板；无离线管理、系统推送或安全原生管理下载。手机127.0.0.1指手机自身。尚不代表商业移动端全能力或50项应用商用验收完成。",
	}
}
