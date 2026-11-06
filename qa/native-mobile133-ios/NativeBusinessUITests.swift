import XCTest
import Vision

final class NativeBusinessUITests: XCTestCase {
    @MainActor private func attach(_ name:String,_ app:XCUIApplication) {
        let ax=XCTAttachment(string:app.debugDescription);ax.name=name+"-original-accessibility";ax.lifetime = .keepAlways;add(ax)
        let picture=XCTAttachment(screenshot:app.screenshot());picture.name=name+"-original-screen";picture.lifetime = .keepAlways;add(picture)
    }
    @MainActor private func visualSystemPoint(_ label:String,_ app:XCUIApplication,header:Bool) throws -> CGVector? {
        // The original OS picker is visibly present while its remote AX tree
        // exposes only an invalid Other/Cancel proxy. Locate actual rendered
        // system text; never tap that hidden proxy or guessed coordinates.
        let shot=app.screenshot(),png=shot.pngRepresentation
        let request=VNRecognizeTextRequest();request.recognitionLevel = .accurate
        request.recognitionLanguages=["en-US"];request.usesLanguageCorrection=false
        // Pass the original encoded screenshot, including image metadata.
        try VNImageRequestHandler(data:png,options:[:]).perform([request])
        let observations=(request.results ?? []).compactMap { observation -> String? in
            guard let text=observation.topCandidates(1).first else {return nil}
            return "confidence="+String(text.confidence)+"; observedText="+text.string+"; box="+String(describing:observation.boundingBox)
        }
        let diagnostic=XCTAttachment(string:"requested="+label+"; originalPNGBytes="+String(png.count)+"; UIImageOrientation="+String(shot.image.imageOrientation.rawValue)+"; VisionRevision="+String(request.revision)+"\n"+observations.joined(separator:"\n"))
        diagnostic.name="original-system-Vision-observations-"+label;diagnostic.lifetime = .keepAlways;add(diagnostic)
        var points:[CGVector]=[]
        for observation in request.results ?? [] {
            guard let text=observation.topCandidates(1).first,text.confidence >= 0.9,
                  let range=text.string.range(of:label),let box=try text.boundingBox(for:range)?.boundingBox else {continue}
            let top=1-box.midY
            guard box.width > 0 && box.height > 0 && box.midX > 0 && box.midX < 1 && top >= 0.05 && top <= (header ? 0.25 : 0.95) else {continue}
            points.append(CGVector(dx:box.midX,dy:top))
        }
        XCTAssertLessThanOrEqual(points.count,1,"Visible system target must be unique: "+label)
        if let point=points.first {
            let picture=XCTAttachment(screenshot:shot);picture.name="original-system-"+label+"-observed-pointer-screen";picture.lifetime = .keepAlways;add(picture)
            let record=XCTAttachment(string:"label="+label+"; normalizedObservedX="+String(describing:point.dx)+"; normalizedObservedTop="+String(describing:point.dy)+"; minimumConfidence=0.9; actualCallbackStillRequired=true")
            record.name="original-system-"+label+"-observed-pointer";record.lifetime = .keepAlways;add(record)
            return point
        }
        return nil
    }
    @MainActor private func tapSystemText(_ label:String,_ app:XCUIApplication,header:Bool) throws {
        let deadline=Date().addingTimeInterval(20)
        repeat {
            if let point=try visualSystemPoint(label,app,header:header) {
                app.coordinate(withNormalizedOffset:point).tap()
                RunLoop.current.run(until:Date().addingTimeInterval(0.4));return
            }
            RunLoop.current.run(until:Date().addingTimeInterval(0.4))
        } while Date() < deadline
        attach("missing-visible-system-"+label,app)
        XCTFail("Actual system text was not visibly selectable: "+label)
    }
    @MainActor private func visible(_ label:String,_ app:XCUIApplication) -> XCUIElement {
        // The system Files hierarchy contains an inaccessible Other named
        // Cancel underneath More. Asking that container for hittability itself
        // records an XCTest failure. Prefer actual observed controls and reject
        // empty/offscreen frames before asking the framework for a hit point.
        let predicate=NSPredicate(format:"label == %@",label)
        let groups=[app.buttons,app.cells,app.links,app.staticTexts,app.textFields]
        for group in groups {
            for element in group.matching(predicate).allElementsBoundByIndex where element.exists {
                let frame=element.frame
                if frame.width > 1 && frame.height > 1 && frame.intersects(app.frame) && element.isHittable { return element }
            }
        }
        return app.buttons.matching(predicate).firstMatch
    }
    @MainActor private func tap(_ label:String,_ app:XCUIApplication) {
        let target=visible(label,app)
        let ready=XCTNSPredicateExpectation(predicate:NSPredicate(format:"exists == true AND hittable == true"),object:target)
        let outcome=XCTWaiter.wait(for:[ready],timeout:20)
        if outcome != .completed { attach("unreachable-control-"+label,app) }
        XCTAssertEqual(outcome,.completed,"Original UI control must become tappable: "+label);target.tap()
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
    @MainActor func testOwnedReceiverStartsBeforeBusiness() {
        continueAfterFailure=false
        let receiver=XCUIApplication(bundleIdentifier:"icu.yunzhan.qa.receiver")
        receiver.launch()
        XCTAssertTrue(receiver.staticTexts["C68 owned local document receiver"].waitForExistence(timeout:30))
        attach("original-owned-provider-receiver-ready",receiver)
        XCUIDevice.shared.press(.home)
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
        save.tap()
        var systemCancellationSubmitted=false
        for step in 0..<3 {
            if let point=try visualSystemPoint("Cancel",app,header:true) {
                app.coordinate(withNormalizedOffset:point).tap();systemCancellationSubmitted=true;break
            }
            attach("original-system-document-sheet-before-visual-back-"+String(step),app)
            try tapSystemText("Browse",app,header:true)
        }
        XCTAssertTrue(systemCancellationSubmitted)
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format:"label BEGINSWITH %@","已取消保存，接收的文件仍可重新选择保存位置。")).firstMatch.waitForExistence(timeout:30))
        XCTAssertTrue(save.isEnabled);save.tap()
        if let point=try visualSystemPoint("Browse",app,header:true) {app.coordinate(withNormalizedOffset:point).tap();RunLoop.current.run(until:Date().addingTimeInterval(0.4))}
        try tapSystemText("On My iPhone",app,header:false)
        try tapSystemText("C68 Receiver",app,header:false)
        try tapSystemText("Save",app,header:true)
        let acknowledgement=app.staticTexts["文件已交给所选文件提供方。请在目标位置确认内容和云端同步状态。"]
        XCTAssertTrue(acknowledgement.waitForExistence(timeout:40));XCTAssertFalse(save.exists);attach("system-provider-export-acknowledged",app)
        // The host independently checks the provider's original filesystem
        // bytes. This app's acknowledgement is never a readback or cloud-sync
        // guarantee. A second received file exercises actual UIKit concealment.
        download.tap();tap("确认",app);XCTAssertTrue(save.waitForExistence(timeout:60));XCTAssertTrue(save.isEnabled)
        XCUIDevice.shared.press(.home);app.activate()
        XCTAssertTrue(app.staticTexts["面板已锁定"].waitForExistence(timeout:30));attach("original-background-state-before-privacy-assertions",app);XCTAssertEqual(app.webViews.count,0);XCTAssertFalse(save.exists)
        XCTAssertFalse(app.staticTexts.containing(NSPredicate(format:"label CONTAINS %@",filename)).firstMatch.exists);attach("background-original-WebView-and-filename-hidden",app)
        tap("退出并重新登录",app);XCTAssertFalse(app.webViews.firstMatch.exists)
        XCTAssertTrue(endpoint.waitForExistence(timeout:20));endpoint.tap()
        // A tap can put the caret in the middle of a retained address. Use
        // the real system Select All keystroke and require an actually empty
        // field before entering the exact cleartext negative input.
        endpoint.typeKey("a",modifierFlags:.command);endpoint.typeText(XCUIKeyboardKey.delete.rawValue)
        let cleared=(endpoint.value as?String) ?? "";XCTAssertTrue(cleared.isEmpty || cleared == "https://你的面板地址/安全入口/")
        endpoint.typeText("http://127.0.0.1:19100/");XCTAssertEqual(endpoint.value as?String,"http://127.0.0.1:19100/");attach("original-release-exact-cleartext-input-before-validation",app);tap("连接",app)
        XCTAssertTrue(app.alerts.firstMatch.waitForExistence(timeout:20));XCTAssertFalse(app.webViews.firstMatch.exists);attach("original-release-refuses-cleartext",app);tap("知道了",app)
    }
}
