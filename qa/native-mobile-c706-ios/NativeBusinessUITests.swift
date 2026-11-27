import XCTest
import Vision
import CoreGraphics

private enum C68SystemTextSelection {
    static func accepts(_ observed:String, confidence:Float, requested:String, header:Bool, box:CGRect) -> Bool {
        // A centered Browse title is not a back control.
        if header && requested == "Browse" && (box.minX < 0 || box.maxX > 0.25) { return false }
        if confidence >= 0.9 { return true }
        // iOS18.5 original Vision revision3 scored the visible chevron plus
        // Browse at0.3. Accept only that exact observed back label and the
        // original left-header region; other labels retain the0.9 rule.
        let top=1-box.midY
        return header && requested == "Browse" && observed == "‹ Browse" && confidence >= 0.3
            && box.minX >= 0 && box.maxX <= 0.25 && top >= 0.05 && top <= 0.25
    }
}

final class NativeBusinessUITests: XCTestCase {
    @MainActor private func attach(_ name:String,_ app:XCUIApplication) {
        let ax=XCTAttachment(string:app.debugDescription);ax.name=name+"-original-accessibility";ax.lifetime = .keepAlways;add(ax)
        let picture=XCTAttachment(screenshot:app.screenshot());picture.name=name+"-original-screen";picture.lifetime = .keepAlways;add(picture)
    }
    @MainActor private func visualSystemPoint(_ label:String,_ app:XCUIApplication,header:Bool) throws -> CGVector? {
        // The original OS picker is visibly present while its remote AX tree
        // exposes only an invalid Other/Cancel proxy. Locate actual rendered
        // system text; never tap that hidden proxy or guessed coordinates.
        // The OS Files UI is hosted remotely. Application screenshots can
        // capture its obscured presenting view, as retained in original QA19.
        let shot=XCUIScreen.main.screenshot(),png=shot.pngRepresentation
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
            guard let text=observation.topCandidates(1).first,
                  let range=text.string.range(of:label),let box=try text.boundingBox(for:range)?.boundingBox else {continue}
            guard C68SystemTextSelection.accepts(text.string,confidence:text.confidence,requested:label,header:header,box:box) else {continue}
            let top=1-box.midY
            if label == "Browse" && !header && (top < 0.75 || box.midX < 0.5) { continue }
            guard box.width > 0 && box.height > 0 && box.midX > 0 && box.midX < 1 && top >= 0.05 && top <= (header ? 0.25 : 0.95) else {continue}
            points.append(CGVector(dx:box.midX,dy:top))
        }
        XCTAssertLessThanOrEqual(points.count,1,"Visible system target must be unique: "+label)
        if let point=points.first {
            let picture=XCTAttachment(screenshot:shot);picture.name="original-system-"+label+"-observed-pointer-screen";picture.lifetime = .keepAlways;add(picture)
            let record=XCTAttachment(string:"label="+label+"; normalizedObservedX="+String(describing:point.dx)+"; normalizedObservedTop="+String(describing:point.dy)+"; rule=exactOriginalTextAndRegionWithRecordedRecognitionEvidence; actualCallbackStillRequired=true")
            record.name="original-system-"+label+"-observed-pointer";record.lifetime = .keepAlways;add(record)
            return point
        }
        return nil
    }
    @MainActor private func tapSystemPoint(_ point:CGVector,_ app:XCUIApplication) {
        let window=app.windows.firstMatch,frame=app.windows.firstMatch.frame
        // Original owned iPhone16Pro screenshots are1206x2622 at3x. The
        // application itself can be transformed below the remote OS sheet.
        XCTAssertTrue(window.exists)
        XCTAssertEqual(frame,CGRect(x:0,y:0,width:402,height:874))
        let geometry=XCTAttachment(string:"actualScreenPointer=true; originalWindowFrame="+String(describing:frame)+"; originalApplicationFrame="+String(describing:app.frame))
        geometry.name="original-system-screen-window-coordinate-binding";geometry.lifetime = .keepAlways;add(geometry)
        window.coordinate(withNormalizedOffset:point).tap()
    }
    @MainActor private func tapSystemText(_ label:String,_ app:XCUIApplication,header:Bool) throws {
        let deadline=Date().addingTimeInterval(90)
        repeat {
            if let point=try visualSystemPoint(label,app,header:header) {
                tapSystemPoint(point,app)
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
    @MainActor private func waitForEnabled(_ target:XCUIElement,_ app:XCUIApplication,_ name:String) {
        // The download control exists while verification is still receiving.
        // Wait for the original actionable state without another download.
        let ready=XCTNSPredicateExpectation(predicate:NSPredicate(format:"exists == true AND enabled == true AND hittable == true"),object:target)
        let outcome=XCTWaiter.wait(for:[ready],timeout:60)
        if outcome != .completed { attach("not-yet-enabled-"+name,app) }
        XCTAssertEqual(outcome,.completed,"Actual original control must finish preparation: "+name)
        XCTAssertTrue(target.exists && target.isEnabled && target.isHittable)
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
        if !(target.exists && target.isHittable) { attach("original-unreachable-top-target",XCUIApplication(bundleIdentifier:"icu.yunzhan.panel")) }
        XCTAssertTrue(target.exists && target.isHittable,"Original top navigation must be reachable")
    }
    @MainActor private func tapObservedWebMenu(_ label:String,_ web:XCUIElement,_ app:XCUIApplication) {
        let deadline=Date().addingTimeInterval(30)
        repeat {
            let values=web.descendants(matching:.any).matching(NSPredicate(format:"label == %@",label)).allElementsBoundByIndex.filter { element in
                guard element.exists,element.isEnabled else {return false}
                let frame=element.frame
                return frame.width > 1 && frame.height > 1 && frame.intersects(web.frame) && frame.intersects(app.frame) && element.isHittable
            }
            if let target=values.min(by:{$0.frame.width*$0.frame.height < $1.frame.width*$1.frame.height}) {
                var common=target.frame
                for value in values { common=common.intersection(value.frame) }
                XCTAssertFalse(common.isNull || common.isEmpty,"One actual observed web menu target required")
                attach("original-actual-web-upload-menu",app);target.tap();return
            }
            RunLoop.current.run(until:Date().addingTimeInterval(0.4))
        } while Date() < deadline
        attach("missing-actual-web-upload-menu",app);XCTFail("Actual observed upload menu target unavailable")
    }
    @MainActor func testOwnedReceiverStartsBeforeBusiness() {
        continueAfterFailure=false
        let receiver=XCUIApplication(bundleIdentifier:"icu.yunzhan.qa.receiver")
        receiver.launch()
        XCTAssertTrue(receiver.staticTexts["C68 owned local document receiver"].waitForExistence(timeout:30))
        attach("original-owned-provider-receiver-ready",receiver)
        XCUIDevice.shared.press(.home)
    }
    @MainActor func testOriginalReleaseHTTPSNativeUploadAndCancellation() throws {
        continueAfterFailure=false
        let values=ProcessInfo.processInfo.environment
        let origin=try XCTUnwrap(values["C68_PANEL_HTTPS"]),username=try XCTUnwrap(values["C68_PANEL_USERNAME"]),password=try XCTUnwrap(values["C68_PANEL_PASSWORD"])
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
        // Original QA21 failed before authentication: the AX password
        // target existed but keystroke dispatch had no keyboard focus.
        // Scroll to the real field and wait for the actual system keyboard
        // before this one password entry; no DOM input or login bypass.
        reveal(secret,in:web);waitForEnabled(secret,app,"real-login-password")
        secret.tap()
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout:30),"Actual login system keyboard must be visible before password input")
        XCTAssertTrue(secret.isHittable && secret.isEnabled)
        RunLoop.current.run(until:Date().addingTimeInterval(0.5))
        secret.typeText(password)
        let enter=web.buttons["进入工作台"];reveal(enter,in:web);enter.tap()
        let navigation=web.buttons["展开导航"];XCTAssertTrue(navigation.waitForExistence(timeout:60));revealTop(navigation,in:web);attach("real-HTTPS-panel-authenticated",app)
        tap("展开导航",app);tap("文件",app)
        let upload=web.otherElements["上传"]
        revealTop(upload,in:web);waitForEnabled(upload,app,"actual-file-upload-toolbar");upload.tap();tapObservedWebMenu("上传文件",web,app)
        attach("original-native-system-upload-picker",app)
        if let point=try visualSystemPoint("Browse",app,header:true) {tapSystemPoint(point,app);RunLoop.current.run(until:Date().addingTimeInterval(0.4))}
        else if let point=try visualSystemPoint("Browse",app,header:false) {tapSystemPoint(point,app);RunLoop.current.run(until:Date().addingTimeInterval(0.4))}
        try tapSystemText("On My iPhone",app,header:false)
        try tapSystemText("C68 Receiver",app,header:false)
        try tapSystemText("C706Upload",app,header:false)
        let status=web.staticTexts.containing(NSPredicate(format:"label BEGINSWITH %@","已上传 1 个文件")).firstMatch
        let deadline=Date().addingTimeInterval(25)
        var submittedOpen=false
        repeat {
            if status.exists && status.isHittable { break }
            if let point=try visualSystemPoint("Open",app,header:true) {
                XCTAssertFalse(submittedOpen);tapSystemPoint(point,app);submittedOpen=true;break
            }
            RunLoop.current.run(until:Date().addingTimeInterval(0.4))
        } while Date() < deadline
        XCTAssertTrue(status.waitForExistence(timeout:60));XCTAssertTrue(status.isHittable)
        attach("actual-native-provider-upload-one-success",app)
        revealTop(upload,in:web);waitForEnabled(upload,app,"upload-toolbar-before-cancel");upload.tap();tapObservedWebMenu("上传文件",web,app)
        attach("original-second-system-upload-picker-before-cancel",app)
        try tapSystemText("Cancel",app,header:true)
        waitForEnabled(upload,app,"actual-native-upload-picker-cancel-returned")
        XCTAssertTrue(status.exists);attach("actual-native-upload-cancel-preserves-page",app)
        tap("清除会话",app);XCTAssertFalse(app.webViews.firstMatch.exists)
        XCTAssertTrue(endpoint.waitForExistence(timeout:20));attach("actual-native-upload-local-session-cleared",app)
    }
}
