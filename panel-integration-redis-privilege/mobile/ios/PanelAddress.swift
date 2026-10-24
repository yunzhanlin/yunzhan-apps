import Foundation

struct PanelAddress: Equatable {
    let url: URL
    private static func components(_ raw: String) throws -> URLComponents {
        guard raw.utf8.count <= 2048, !raw.isEmpty,
              raw.unicodeScalars.allSatisfy({ $0.value > 32 && $0.value < 127 }), !raw.contains("\\"),
              let c = URLComponents(string: raw), c.scheme != nil, let host = c.host, !host.isEmpty,
              c.user == nil, c.password == nil, !(c.percentEncodedHost ?? "").contains("%"),
              c.port == nil || (1...65535).contains(c.port!), c.url != nil else { throw InvalidAddress() }
        return c
    }
    init(_ raw: String, debug: Bool = false) throws {
        var c = try Self.components(raw)
        let scheme = c.scheme!.lowercased(), host = c.host!.lowercased()
        let loopback = ["127.0.0.1", "localhost", "[::1]", "::1"].contains(host)
        guard (scheme == "https" || (debug && scheme == "http" && loopback)), c.query == nil, c.fragment == nil,
              !c.path.split(separator: "/").contains(".."), !c.path.split(separator: "/").contains(".") else { throw InvalidAddress() }
        if c.path.isEmpty { c.path = "/" }
        url = c.url!
    }
    func allows(_ candidate: URL) -> Bool {
        guard let a = try? Self.components(url.absoluteString), let b = try? Self.components(candidate.absoluteString),
              a.scheme?.lowercased() == b.scheme?.lowercased(), a.host?.lowercased() == b.host?.lowercased() else { return false }
        let p1 = a.port ?? (a.scheme?.lowercased() == "https" ? 443 : 80)
        let p2 = b.port ?? (b.scheme?.lowercased() == "https" ? 443 : 80)
        return p1 == p2
    }
    var origin: String {
        var c = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        c.path = ""; c.query = nil; c.fragment = nil; return c.url!.absoluteString
    }
    struct InvalidAddress: LocalizedError {
        var errorDescription: String? { "请输入完整 HTTPS 面板地址，不含账号、查询参数、临时令牌或片段。" }
    }
}
