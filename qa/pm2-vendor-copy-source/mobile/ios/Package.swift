// swift-tools-version: 5.10
import PackageDescription
let package = Package(name: "PanelAddress", platforms: [.macOS(.v13), .iOS("18.4")], products: [.library(name: "PanelAddress", targets: ["PanelAddress"])], targets: [
    .target(name: "PanelAddress", path: ".", exclude: ["YunzhanMobile.swift", "Info.plist", "PrivacyInfo.xcprivacy", "YunzhanMobile.xcodeproj", "Tests"], sources: ["PanelAddress.swift", "SessionCallbacks.swift", "NativeDownloadMetadata.swift", "ForegroundFileDownload.swift"]),
    .testTarget(name: "PanelAddressTests", dependencies: ["PanelAddress"], path: "Tests")
])
