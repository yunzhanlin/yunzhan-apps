import Foundation
import XCTest
@testable import PanelAddress
final class PanelAddressTests: XCTestCase {
    func testExactOrigin() throws {
        let a = try PanelAddress("https://panel.example:2443/private/")
        XCTAssertTrue(a.allows(URL(string: "https://panel.example:2443/api/me?x=1")!))
        for raw in ["http://panel.example:2443/", "https://panel.example/", "https://panel.example.evil:2443/", "https://evil@panel.example:2443/", "file:///private/", "https://%70anel.example:2443/", "javascript://panel.example:2443/"] {
            XCTAssertFalse(a.allows(URL(string: raw)!), raw)
        }
        XCTAssertTrue(try PanelAddress("https://panel.example/").allows(URL(string: "https://panel.example:443/api/me")!))
    }
    func testRejectCredentialsQueryAndMalformed() throws {
        for raw in ["http://panel.example/", "https://u:p@panel.example/", "https://panel.example/?tmp_token=x", "https://panel.example/#token", "https://panel.example/../root/", "https://panel.example:99999/", "https://panel.example:0/", "https://panel.example\n/", "https://面板.example/", "https://panel.example\\/"] {
            XCTAssertThrowsError(try PanelAddress(raw), raw)
        }
    }
    func testDebugOnlyLoopback() throws {
        XCTAssertNoThrow(try PanelAddress("http://127.0.0.1:19220/", debug: true))
        XCTAssertThrowsError(try PanelAddress("http://127.0.0.1:19220/"))
        XCTAssertThrowsError(try PanelAddress("http://192.168.1.1/", debug: true))
    }
}
