// swift-tools-version: 5.10
import PackageDescription
let package = Package(name: "PanelAddress", products: [.library(name: "PanelAddress", targets: ["PanelAddress"])], targets: [
    .target(name: "PanelAddress", path: ".", exclude: ["YunzhanMobile.swift", "Info.plist", "YunzhanMobile.xcodeproj", "Tests"], sources: ["PanelAddress.swift"]),
    .testTarget(name: "PanelAddressTests", dependencies: ["PanelAddress"], path: "Tests")
])
