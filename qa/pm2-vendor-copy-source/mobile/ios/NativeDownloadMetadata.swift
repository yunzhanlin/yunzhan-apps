import Foundation

struct NativeDownloadMetadata: Sendable {
    let filename: String
    let mime: String
    let length: Int64?
    let serverDigest: String?
    init(disposition: String?, mime: String?, length: String?, encoding: String?, digest: String?) throws {
        guard let disposition, disposition.utf8.count <= 8192,
              !disposition.utf8.contains(13), !disposition.utf8.contains(10) else { throw NativeDownloadFailure.response }
        var fields: [String] = [], current = "", quoted = false, escaped = false
        for ch in disposition {
            if escaped { current.append(ch); escaped = false; continue }
            if quoted && ch == "\\" { current.append(ch); escaped = true; continue }
            if ch == "\"" { quoted.toggle() }
            if ch == ";" && !quoted { fields.append(current); current = "" } else { current.append(ch) }
        }
        guard !quoted && !escaped else { throw NativeDownloadFailure.response }
        fields.append(current)
        guard fields.first?.trimmingCharacters(in: .whitespaces).lowercased() == "attachment" else { throw NativeDownloadFailure.response }
        var ordinary: String?, extended: String?
        for field in fields.dropFirst() {
            guard let equal = field.firstIndex(of: "=") else { continue }
            let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            var value = field[field.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            if key == "filename" {
                guard ordinary == nil else { throw NativeDownloadFailure.response }
                if value.hasPrefix("\"") {
                    guard value.count >= 2 && value.hasSuffix("\"") else { throw NativeDownloadFailure.response }
                    value = String(value.dropFirst().dropLast())
                    var output = "", escape = false
                    for ch in value {
                        if escape { output.append(ch); escape = false }
                        else if ch == "\\" { escape = true } else { output.append(ch) }
                    }
                    guard !escape else { throw NativeDownloadFailure.response }; value = output
                }
                ordinary = value
            } else if key == "filename*" {
                guard extended == nil else { throw NativeDownloadFailure.response }
                let parts = value.split(separator: "'", maxSplits: 2, omittingEmptySubsequences: false)
                guard parts.count == 3 && parts[0].lowercased() == "utf-8",
                      parts[2].unicodeScalars.allSatisfy({ $0.value > 32 && $0.value < 127 }),
                      let decoded = String(parts[2]).removingPercentEncoding else { throw NativeDownloadFailure.response }
                extended = decoded
            }
        }
        filename = Self.safeName(extended ?? ordinary)
        let type = (mime ?? "").split(separator: ";", maxSplits: 1).first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
        self.mime = type.utf8.count <= 128 && type.range(of: "^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$", options: .regularExpression) != nil ? type.lowercased() : "application/octet-stream"
        if let length {
            guard length.range(of: "^[0-9]{1,19}$", options: .regularExpression) != nil, let parsed = Int64(length) else { throw NativeDownloadFailure.response }
            self.length = parsed
        } else { self.length = nil }
        if let digest, !digest.trimmingCharacters(in: .whitespaces).isEmpty {
            let normalized = digest.trimmingCharacters(in: .whitespaces).lowercased()
            guard normalized.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw NativeDownloadFailure.response }
            serverDigest = normalized
        } else { serverDigest = nil }
        guard encoding == nil || encoding!.trimmingCharacters(in: .whitespaces).isEmpty || encoding!.lowercased() == "identity" else { throw NativeDownloadFailure.response }
    }
    init(_ response: HTTPURLResponse) throws {
        try self.init(disposition: response.value(forHTTPHeaderField: "Content-Disposition"), mime: response.value(forHTTPHeaderField: "Content-Type"), length: response.value(forHTTPHeaderField: "Content-Length"), encoding: response.value(forHTTPHeaderField: "Content-Encoding"), digest: response.value(forHTTPHeaderField: "X-Content-SHA256"))
        guard response.value(forHTTPHeaderField: "Transfer-Encoding") == nil || length == nil else { throw NativeDownloadFailure.response }
    }
    static func safeName(_ source: String?) -> String {
        guard let source else { return "yunzhan-download.bin" }
        var value = "", bytes = 0
        for scalar in source.unicodeScalars {
            let unsafe = scalar == "/" || scalar == "\\" || CharacterSet.controlCharacters.contains(scalar) || scalar.properties.generalCategory == .format || scalar.properties.generalCategory == .surrogate
            let part = unsafe ? "_" : String(scalar)
            guard bytes + part.utf8.count <= 180 else { break }; bytes += part.utf8.count; value += part
        }
        value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty || value == "." || value == ".." ? "yunzhan-download.bin" : value
    }
}

enum NativeDownloadFailure: Error, LocalizedError, Sendable, Equatable {
    case cancelled, response, network, capacity, integrity, storage, busy
    var errorDescription: String? {
        switch self {
        case .cancelled: return "下载已停止，未完成的文件没有导出。"
        case .response: return "附件响应无效。请检查登录状态、文件类型或下载地址。"
        case .network: return "下载连接中断，请检查网络和可信 HTTPS 证书。"
        case .capacity: return "空间不足或附件超过 2 GiB，已停止接收。"
        case .integrity: return "文件长度或摘要不符，未提供保存。"
        case .storage: return "私有下载缓存不可用，原有未知文件得到保留。"
        case .busy: return "原传输仍在收尾，请稍后重试。"
        }
    }
}

enum NativeDownloadCookies {
    static func header(_ cookies: [HTTPCookie], for url: URL, now: Date = Date()) throws -> String {
        guard let host = url.host?.lowercased() else { throw NativeDownloadFailure.response }
        let path = url.path.isEmpty ? "/" : url.path
        let selected = cookies.filter { cookie in
            let domain = cookie.domain.lowercased()
            let matches = domain.hasPrefix(".") ? host == String(domain.dropFirst()) || host.hasSuffix(domain) : host == domain
            let cookiePath = cookie.path.isEmpty ? "/" : cookie.path
            return matches && (!cookie.isSecure || url.scheme?.lowercased() == "https") && (cookie.expiresDate == nil || cookie.expiresDate! > now)
                && (path == cookiePath || path.hasPrefix(cookiePath.hasSuffix("/") ? cookiePath : cookiePath + "/"))
        }.sorted { $0.path.count > $1.path.count }
        let header = HTTPCookie.requestHeaderFields(with: selected)["Cookie"] ?? ""
        guard header.utf8.count <= 32768 && header.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 }) else { throw NativeDownloadFailure.response }
        return header
    }
}
