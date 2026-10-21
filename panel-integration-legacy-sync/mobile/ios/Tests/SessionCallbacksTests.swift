import XCTest
@testable import PanelAddress

final class SessionCallbacksTests: XCTestCase {
    func testPickerRequiresUnlockAfterBackgroundAndDeliversOnlyOnce() throws {
        var s = SessionCallbacks<String>(); s.start(); let picker = try XCTUnwrap(s.beginSelection())
        s.cover(background: true); XCTAssertTrue(s.receiveSelection(picker, value: "private-file")); XCTAssertNil(s.takeSelection())
        s.activate(); XCTAssertNil(s.takeSelection()); let auth = try XCTUnwrap(s.beginAuthentication())
        XCTAssertTrue(s.finishAuthentication(auth, success: true)); XCTAssertEqual(s.takeSelection()?.value, "private-file"); XCTAssertNil(s.takeSelection())
        XCTAssertFalse(s.receiveSelection(picker, value: "duplicate")); XCTAssertFalse(s.finishAuthentication(auth, success: true))
    }
    func testInactivePromptSuccessIsNotUnlockedUntilActive() throws {
        var s = SessionCallbacks<String>(); s.start(); s.cover(background: true); s.activate(); let auth = try XCTUnwrap(s.beginAuthentication())
        s.cover(background: false); XCTAssertTrue(s.finishAuthentication(auth, success: true)); XCTAssertTrue(s.locked); XCTAssertFalse(s.interactive)
        s.activate(); XCTAssertFalse(s.locked); XCTAssertTrue(s.interactive)
    }
    func testBackgroundRevokesBothPendingAuthenticationAndInactiveSuccess() throws {
        var s = SessionCallbacks<String>(); s.start(); s.cover(background: true); s.activate(); let old = try XCTUnwrap(s.beginAuthentication())
        s.cover(background: true); XCTAssertFalse(s.finishAuthentication(old, success: true)); s.activate()
        let next = try XCTUnwrap(s.beginAuthentication()); s.cover(background: false); XCTAssertTrue(s.finishAuthentication(next, success: true))
        s.cover(background: true); s.activate(); XCTAssertTrue(s.locked); XCTAssertNotNil(s.beginAuthentication())
    }
    func testOldPickerAndAuthCannotEnterNewSessionAtSameOrigin() throws {
        var s = SessionCallbacks<String>(); s.start(); let picker = try XCTUnwrap(s.beginSelection()); s.cover(background: true); s.activate(); let old = try XCTUnwrap(s.beginAuthentication())
        s.end(); s.start(); let current = try XCTUnwrap(s.beginSelection()); XCTAssertFalse(s.receiveSelection(picker, value: "stale"))
        s.cover(background: true); s.activate(); let auth = try XCTUnwrap(s.beginAuthentication()); XCTAssertFalse(s.finishAuthentication(old, success: true)); XCTAssertTrue(s.locked)
        XCTAssertTrue(s.receiveSelection(current, value: nil)); XCTAssertTrue(s.finishAuthentication(auth, success: true)); XCTAssertNotNil(s.takeSelection()); XCTAssertNil(s.takeSelection())
    }
    func testCancelledAuthenticationAndDuplicatePickerCannotReplaceOriginal() throws {
        var s = SessionCallbacks<String>(); s.start(); let picker = try XCTUnwrap(s.beginSelection()); XCTAssertNil(s.beginSelection())
        s.cover(background: true); s.activate(); let auth = try XCTUnwrap(s.beginAuthentication()); XCTAssertFalse(s.finishAuthentication(auth, success: false))
        XCTAssertTrue(s.receiveSelection(picker, value: "first")); XCTAssertFalse(s.receiveSelection(picker, value: "second")); XCTAssertNil(s.takeSelection())
        XCTAssertTrue(s.finishAuthentication(try XCTUnwrap(s.beginAuthentication()), success: true)); XCTAssertEqual(s.takeSelection()?.value, "first")
    }
    func testInactivePickerWaitsForActiveWithoutManufacturingDeviceAuthentication() throws {
        var s = SessionCallbacks<String>(); s.start(); let picker = try XCTUnwrap(s.beginSelection()); s.cover(background: false)
        XCTAssertTrue(s.receiveSelection(picker, value: "file")); XCTAssertNil(s.takeSelection()); XCTAssertNil(s.beginAuthentication()); s.activate()
        XCTAssertEqual(s.takeSelection()?.value, "file"); XCTAssertNil(s.takeSelection()); s.end(); XCTAssertNil(s.beginSelection())
    }
}
