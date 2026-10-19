package core

// Fixed, built-and-verified artifacts. Never accept download URLs from module
// settings. Private signing keys are not part of the panel or repository.
func NativeMobileDelivery() map[string]any {
	const release = "https://github.com/yunzhanlin/yunzhan-apps/releases/download/v0.1.0-dev.proapps11/"
	return map[string]any{
		"manifest": "/manifest.webmanifest", "installable": true,
		"version": "1.3.0", "delivery_model": "原生安全容器 + 真实面板响应式业务页", "session_model": "HTTPS + HttpOnly + SameSite + CSRF + TOTP + 原角色与网站范围",
		"android_signer_sha256": "0ba923afca85db94f4bdabd6d235fcf1c7088bb167ace661bf21781d1c7f0bd5",
		"mobile_downloads": []map[string]string{
			{"name": "Android APK", "platform": "Android 11+", "filename": "yunzhan-mobile-1.3.0-android.apk", "url": release + "yunzhan-mobile-1.3.0-android.apk", "sha256": "45dd8bc7048ad0df15805dc1887f509b8905390eace6a223c552c9425fc74db2", "state": "独立发布签名，可安装；正式包只连接 HTTPS"},
			{"name": "iOS 未签名设备构建", "platform": "iOS 18.4+ / arm64", "filename": "yunzhan-mobile-1.3.0-ios-unsigned.tar.gz", "url": release + "yunzhan-mobile-1.3.0-ios-unsigned.tar.gz", "sha256": "272d6ffbf0b636b121311f6565f3203ae4f460852d023db3882523507071c219", "state": "需要自己的开发者签名；不是可直接安装的 IPA"},
			{"name": "Android + iOS 源码", "platform": "Gradle / Xcode", "filename": "yunzhan-mobile-1.3.0-source.tar.gz", "url": release + "yunzhan-mobile-1.3.0-source.tar.gz", "sha256": "797f47e79e8ef799c813fc9a6c2c9ce2f56e8cb159c8896defbcfed1b61e865d", "state": "可构建、无生产私钥和账号密码"},
		},
		"scope": "原生地址校验、可信 TLS、设备认证、后台锁屏、会话清除及文件选择；业务页来自实际面板，不是模拟数据。无离线管理、系统推送或自动后台运维。手机 127.0.0.1 指手机自身，不是电脑。APK 编译、签名与模拟器启动，iOS 设备/模拟器编译和 URL 测试已验证；尚不代表全部移动业务实机验收或商业版全能力完成。",
	}
}
