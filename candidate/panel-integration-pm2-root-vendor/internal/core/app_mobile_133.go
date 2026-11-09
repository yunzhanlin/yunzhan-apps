package core

// This cohort is independent of the retained 1.3.2 installation. URLs and
// digests are fixed publisher outputs, never values supplied by app settings.
func nativeMobile133Delivery() map[string]any {
	const release = "https://github.com/yunzhanlin/yunzhan-apps/releases/download/mobile-v1.3.3/"
	return map[string]any{
		"manifest": "/manifest.webmanifest", "installable": true,
		"version":                             "1.3.3",
		"delivery_model":                      "原生安全容器 + 面板实际业务页",
		"session_model":                       "HTTPS、面板登录、双重验证、原角色与网站权限",
		"native_source_inputs_sha256":         "895c674a1c3475f934df1b2289fa3b01e613b16c5cad46f60f8bdc36739e680e",
		"android_signer_sha256":               "0ba923afca85db94f4bdabd6d235fcf1c7088bb167ace661bf21781d1c7f0bd5",
		"physical_device_acceptance":          false,
		"android_target_sdk":                  37,
		"android_emulator_session_acceptance": true, "android_emulator_api": 37,
		"ios_accessibility_ui_acceptance":                            false,
		"ios_emulator_file_export_and_background_privacy_acceptance": true,
		"mobile_downloads": []map[string]string{
			{"name": "Android APK", "platform": "Android 11+ / 需更新系统 WebView", "filename": "yunzhan-mobile-1.3.3-android.apk", "url": release + "yunzhan-mobile-1.3.3-android.apk", "sha256": "a60a6d022fe932be837807ad27745cc362bb85bd2bf85af89ad2082b6ed9db74", "state": "原发布者签名；安装后填写自己的 HTTPS 面板地址并登录"},
			{"name": "iOS 未签名设备构建", "platform": "iOS 18.4+ / arm64", "filename": "yunzhan-mobile-1.3.3-ios-unsigned.tar.gz", "url": release + "yunzhan-mobile-1.3.3-ios-unsigned.tar.gz", "sha256": "7398fc9cd319232d5983dcffebddc2a53a6d6f3705925b1f0d56c5698bb9f882", "state": "需使用自己的开发者签名；此文件不是可直接安装的 IPA"},
			{"name": "Android + iOS 源码", "platform": "Gradle / Xcode", "filename": "yunzhan-mobile-1.3.3-source.tar.gz", "url": release + "yunzhan-mobile-1.3.3-source.tar.gz", "sha256": "ee40e9c48470a6d1e6f16d895a28be61f2ae045cfd4e5c4dd4e5fe8458f38567", "state": "包含完整构建源码及依赖许可，无生产密钥和账号密码"},
		},
		"scope": "在应用内登录实际面板，业务权限沿用面板设置。支持前台附件下载，单文件最多 2 GiB、最长 5 分钟；切到后台停止未完成的传输。Android 保存后重新读取核对摘要，iOS 交给系统文件提供方后请在目标位置确认内容与云端同步。返回后台会锁定网页，需设备认证或退出后重新登录。Android 请通过系统应用商店更新 WebView 至最新稳定版；最低页面兼容内核为 Chromium 111。手机的 127.0.0.1 指手机自身。此版本需要联网，不提供离线管理或系统推送。",
	}
}
