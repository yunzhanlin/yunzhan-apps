import XCTest

final class NativeBusinessUITests: XCTestCase {
    @MainActor private func attach(_ name:String,_ app:XCUIApplication) {
        let ax=XCTAttachment(string:app.debugDescription);ax.name=name+"-original-accessibility";ax.lifetime = .keepAlways;add(ax)
        let picture=XCTAttachment(screenshot:app.screenshot());picture.name=name+"-original-screen";picture.lifetime = .keepAlways;add(picture)
    }
    @MainActor private func visible(_ label:String,_ app:XCUIApplication) -> XCUIElement {
        let all=app.descendants(matching:.any).matching(NSPredicate(format:"label == %@",label))
        for element in all.allElementsBoundByIndex where element.exists && element.isHittable { return element }
        return all.firstMatch
    }
    @MainActor private func tap(_ label:String,_ app:XCUIApplication) {
        let target=visible(label,app),exists=target.waitForExistence(timeout:20)
        if !exists || !target.isHittable { attach("unreachable-control-"+label,app) }
        XCTAssertTrue(exists,"Original UI label missing: "+label);XCTAssertTrue(target.isHittable,"Original UI label not tappable: "+label);target.tap()
    }
    @MainActor private func reveal(_ target:XCUIElement,in view:XCUIElement) {
        for _ in 0..<6 { if target.exists && target.isHittable{return};view.swipeUp() }
        XCTAssertTrue(target.exists && target.isHittable,"Original business control must be visible")
    }
    @MainActor private func revealTop(_ target:XCUIElement,in view:XCUIElement) {
        // The SPA retains the login form's real scroll position. Return with
        // ordinary user gestures; never tap offscreen AX coordinates or inject
        // page scrolling/scripts as a substitute for a reachable control.
        for _ in 0..<6 { if target.exists && target.isHittable{return};view.swipeDown() }
        XCTAssertTrue(target.exists && target.isHittable,"Original top navigation must be reachable")
    }
    @MainActor func testOriginalReleaseHTTPSFileManagementExportAndBackgroundPrivacy() throws {
        continueAfterFailure=false
        let values=ProcessInfo.processInfo.environment
        let origin=try XCTUnwrap(values["C68_PANEL_HTTPS"]),username=try XCTUnwrap(values["C68_PANEL_USERNAME"]),password=try XCTUnwrap(values["C68_PANEL_PASSWORD"]),filename=try XCTUnwrap(values["C68_ATTACHMENT_FILENAME"])
        XCTAssertTrue(origin.hasPrefix("https://") && origin.hasSuffix(".trycloudflare.com"))
        let app=XCUIApplication(bundleIdentifier:"icu.yunzhan.panel");app.launchArguments=["-AppleLanguages","(en)","-AppleLocale","en_US"];app.launch()
        let endpoint=app.textFields["https://你的面板地址/安全入口/"];XCTAssertTrue(endpoint.waitForExistence(timeout:30));endpoint.tap();endpoint.typeText(origin+"/");tap("连接",app)
        let web=app.webViews.firstMatch;XCTAssertTrue(web.waitForExistence(timeout:60))
        let user=web.textFields["管理员用户名"],secret=web.secureTextFields["输入管理员密码"]
        XCTAssertTrue(user.waitForExistence(timeout:60))
        let existing=(user.value as?String) ?? ""
        if existing != username {
            user.tap()
            if !existing.isEmpty && existing != "管理员用户名" { XCTAssertLessThanOrEqual(existing.count,64);user.typeText(String(repeating:XCUIKeyboardKey.delete.rawValue,count:existing.count)) }
            user.typeText(username)
        }
        secret.tap();secret.typeText(password)
        let enter=web.buttons["进入工作台"];reveal(enter,in:web);enter.tap()
        let navigation=web.buttons["展开导航"];XCTAssertTrue(navigation.waitForExistence(timeout:60));revealTop(navigation,in:web);attach("real-HTTPS-panel-authenticated",app)
        tap("展开导航",app);tap("文件",app)
        let row=web.otherElements["查看 "+filename+" 的文件信息"];reveal(row,in:web)
        let download=row.links["下载"];XCTAssertTrue(download.exists);download.tap();tap("确认",app)
        let save=app.buttons["选择保存位置"];XCTAssertTrue(save.waitForExistence(timeout:60));XCTAssertTrue(save.isEnabled);attach("original-native-attachment-received",app)
        save.tap();tap("Cancel",app)
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format:"label BEGINSWITH %@","已取消保存，接收的文件仍可重新选择保存位置。")).firstMatch.waitForExistence(timeout:30))
        XCTAssertTrue(save.isEnabled);save.tap()
        let browse=visible("Browse",app)
        if browse.exists && browse.isHittable { browse.tap() }
        tap("On My iPhone",app);tap("C68 Receiver",app)
        let systemSave=visible("Save",app);XCTAssertTrue(systemSave.waitForExistence(timeout:30));XCTAssertTrue(systemSave.isHittable);systemSave.tap()
        let acknowledgement=app.staticTexts["文件已交给所选文件提供方。请在目标位置确认内容和云端同步状态。"]
        XCTAssertTrue(acknowledgement.waitForExistence(timeout:40));XCTAssertFalse(save.exists);attach("system-provider-export-acknowledged",app)
        // The host independently checks the provider's original filesystem
        // bytes. This app's acknowledgement is never a readback or cloud-sync
        // guarantee. A second received file exercises actual UIKit concealment.
        download.tap();tap("确认",app);XCTAssertTrue(save.waitForExistence(timeout:60));XCTAssertTrue(save.isEnabled)
        XCUIDevice.shared.press(.home);app.activate()
        XCTAssertTrue(app.staticTexts["面板已锁定"].waitForExistence(timeout:30));XCTAssertEqual(app.webViews.count,0);XCTAssertFalse(save.exists)
        XCTAssertFalse(app.staticTexts.containing(NSPredicate(format:"label CONTAINS %@",filename)).firstMatch.exists);attach("background-original-WebView-and-filename-hidden",app)
        tap("退出并重新登录",app);XCTAssertFalse(app.webViews.firstMatch.exists)
        XCTAssertTrue(endpoint.waitForExistence(timeout:20));endpoint.tap()
        let current=(endpoint.value as?String) ?? "";endpoint.typeText(String(repeating:XCUIKeyboardKey.delete.rawValue,count:current.count));endpoint.typeText("http://127.0.0.1:19100/");tap("连接",app)
        XCTAssertTrue(app.alerts.firstMatch.waitForExistence(timeout:20));XCTAssertFalse(app.webViews.firstMatch.exists);attach("original-release-refuses-cleartext",app);tap("知道了",app)
    }
}
