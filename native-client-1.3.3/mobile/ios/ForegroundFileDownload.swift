import Foundation
import CryptoKit
import Darwin

struct NativeDownloadedFile: Sendable {
    let url: URL
    let metadata: NativeDownloadMetadata
    let bytes: Int64
    let sha256: String
    func discard() { NativeDownloadCache.discard(url) }
}

private enum NativeDownloadBudget {
    static let lock = NSLock()
    static var held = false
    static func acquire() -> Bool { lock.lock(); defer { lock.unlock() }; guard !held else { return false }; held = true; return true }
    static func release() { lock.lock(); held = false; lock.unlock() }
}

enum NativeDownloadCache {
    private static let lock = NSLock()
    private static var prepared = Set<URL>()
    static func prepare(_ cache: URL) throws -> URL {
        lock.lock(); defer { lock.unlock() }
        let root = cache.appendingPathComponent("native-downloads", isDirectory: true)
        var state = stat()
        if lstat(root.path, &state) != 0 {
            guard errno == ENOENT else { throw NativeDownloadFailure.storage }
            var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
            #if os(iOS)
            attributes[.protectionKey] = FileProtectionType.complete
            #endif
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: attributes)
        }
        guard lstat(root.path, &state) == 0, state.st_mode & S_IFMT == S_IFDIR, state.st_mode & 0o7777 == 0o700, state.st_uid == getuid() else { throw NativeDownloadFailure.storage }
        if prepared.contains(root) { return root }
        guard NativeDownloadBudget.acquire() else { throw NativeDownloadFailure.busy }; defer { NativeDownloadBudget.release() }
        guard let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil, options: [.skipsSubdirectoryDescendants]) else { throw NativeDownloadFailure.storage }
        var count = 0
        for case let file as URL in files {
            count += 1; guard count <= 128 else { throw NativeDownloadFailure.storage }
            guard lstat(file.path, &state) == 0, state.st_uid == getuid() else { throw NativeDownloadFailure.storage }
            if isNamedDirectory(file) {
                guard state.st_mode & S_IFMT == S_IFDIR, state.st_mode & 0o7777 == 0o700,
                      let children = FileManager.default.enumerator(at:file,includingPropertiesForKeys:nil,options:[.skipsSubdirectoryDescendants]) else { throw NativeDownloadFailure.storage }
                var entries:[URL] = []
                for case let child as URL in children { entries.append(child); guard entries.count <= 1 else { throw NativeDownloadFailure.storage } }
                if let child = entries.first {
                    guard NativeDownloadMetadata.safeName(child.lastPathComponent) == child.lastPathComponent else { throw NativeDownloadFailure.storage }
                    try removeKnownFile(child)
                }
                guard rmdir(file.path) == 0 else { throw NativeDownloadFailure.storage }
            } else {
                guard file.lastPathComponent.range(of: "^download-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.part$", options: .regularExpression) != nil else { throw NativeDownloadFailure.storage }
                try removeKnownFile(file)
            }
        }
        prepared.insert(root); return root
    }
    private static func isNamedDirectory(_ path:URL) -> Bool { path.lastPathComponent.range(of:"^download-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",options:.regularExpression) != nil }
    private static func removeKnownFile(_ path:URL) throws {
        var value=stat()
        guard lstat(path.path,&value)==0,value.st_mode & S_IFMT == S_IFREG,value.st_mode & 0o7777 == 0o600,value.st_uid==getuid(),value.st_nlink==1,value.st_size>=0,value.st_size<=ForegroundFileDownload.maximumBytes else { throw NativeDownloadFailure.storage }
        guard unlink(path.path)==0 else { throw NativeDownloadFailure.storage }
    }
    static func displayName(_ original:URL, filename:String) throws -> URL {
        guard NativeDownloadMetadata.safeName(filename)==filename else { throw NativeDownloadFailure.storage }
        let directory=original.deletingLastPathComponent().appendingPathComponent("download-"+UUID().uuidString.lowercased(),isDirectory:true)
        guard mkdir(directory.path,0o700)==0 else { throw NativeDownloadFailure.storage }
        let target=directory.appendingPathComponent(filename)
        guard rename(original.path,target.path)==0 else { _ = rmdir(directory.path);throw NativeDownloadFailure.storage }
        return target
    }
    static func discard(_ file:URL) {
        file.withUnsafeFileSystemRepresentation { name in if let name { _ = unlink(name) } }
        let parent=file.deletingLastPathComponent();if isNamedDirectory(parent) { _ = rmdir(parent.path) }
    }
}

/// A serial streaming receiver; credentials remain inside this app's process.
final class ForegroundFileDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    static let maximumBytes: Int64 = 2 * 1024 * 1024 * 1024
    static let reserveBytes: Int64 = 128 * 1024 * 1024
    private let address: PanelAddress
    private let target: URL
    private let directory: URL
    private var cookie: String
    private let completion: @Sendable (Result<NativeDownloadedFile, NativeDownloadFailure>) -> Void
    private let progress: @Sendable (Int64, Int64?) -> Void
    private let queue = OperationQueue()
    private let lock = NSLock()
    private var cancelled = false
    private var started = false
    private var session: URLSession?
    private var task: URLSessionDataTask?
    // Everything below is owned exclusively by the serial delegate queue.
    private var terminal = false, leased = false
    private var file: FileHandle?
    private var path: URL?
    private var metadata: NativeDownloadMetadata?
    private var received: Int64 = 0
    private var digest = SHA256()
    private var lastProgress: TimeInterval = 0
    private let maximum: Int64
    private let reserve: Int64
    init(address: PanelAddress, url: URL, cookie: String, directory: URL, maximum: Int64 = maximumBytes, reserve: Int64 = reserveBytes,
         progress: @escaping @Sendable (Int64, Int64?) -> Void, completion: @escaping @Sendable (Result<NativeDownloadedFile, NativeDownloadFailure>) -> Void) throws {
        guard address.allows(url), maximum > 0, maximum <= Self.maximumBytes, reserve >= 0,
              cookie.utf8.count <= 32768, cookie.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 }) else { throw NativeDownloadFailure.response }
        self.address = address; target = url; self.cookie = cookie; self.directory = directory; self.maximum = maximum; self.reserve = reserve
        self.progress = progress; self.completion = completion
        super.init(); queue.maxConcurrentOperationCount = 1; queue.name = "panel-foreground-download"
    }
    private var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    func start() {
        lock.lock(); guard !started else { lock.unlock(); return }; started = true; lock.unlock()
        queue.addOperation { [self] in
            guard !isCancelled else { finish(.failure(.cancelled)); return }
            guard NativeDownloadBudget.acquire() else { finish(.failure(.busy)); return }; leased = true
            do {
                try capacity(1)
                let configuration = URLSessionConfiguration.ephemeral
                configuration.httpCookieStorage = nil; configuration.httpShouldSetCookies = false; configuration.urlCredentialStorage = nil; configuration.urlCache = nil
                configuration.timeoutIntervalForRequest = 15; configuration.timeoutIntervalForResource = 300; configuration.httpMaximumConnectionsPerHost = 1; configuration.waitsForConnectivity = false
                let transport = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
                var request = URLRequest(url: target, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
                request.httpMethod = "GET"; request.setValue("identity", forHTTPHeaderField: "Accept-Encoding"); request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
                request.setValue("YunzhanMobile/1.3.3", forHTTPHeaderField: "User-Agent")
                if !cookie.isEmpty { request.setValue(cookie, forHTTPHeaderField: "Cookie") }; cookie = ""
                let work = transport.dataTask(with: request)
                lock.lock(); session = transport; task = work; let stopped = cancelled; lock.unlock()
                if stopped { finish(.failure(.cancelled)) } else { work.resume() }
            } catch { finish(.failure(error as? NativeDownloadFailure ?? .storage)) }
        }
    }
    func cancel() {
        lock.lock(); cancelled = true; let transport = session; lock.unlock(); transport?.invalidateAndCancel()
        queue.addOperation { [self] in finish(.failure(.cancelled)) }
    }
    private func capacity(_ additional: Int64) throws {
        guard !isCancelled else { throw NativeDownloadFailure.cancelled }
        var state = stat()
        guard lstat(directory.path, &state) == 0, state.st_mode & S_IFMT == S_IFDIR, state.st_mode & 0o7777 == 0o700, state.st_uid == getuid() else { throw NativeDownloadFailure.storage }
        let attributes = try FileManager.default.attributesOfFileSystem(forPath: directory.path)
        guard let available = (attributes[.systemFreeSize] as? NSNumber)?.int64Value, available - reserve >= additional else { throw NativeDownloadFailure.capacity }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard !terminal, !isCancelled, dataTask === task, let response = response as? HTTPURLResponse, response.statusCode == 200,
              let url = response.url, address.allows(url) else { completionHandler(.cancel); finish(.failure(isCancelled ? .cancelled : .response)); return }
        do {
            let value = try NativeDownloadMetadata(response)
            if let length = value.length { guard length <= maximum else { throw NativeDownloadFailure.capacity }; try capacity(length) }
            let destination = directory.appendingPathComponent("download-" + UUID().uuidString.lowercased() + ".part")
            let descriptor = open(destination.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { throw NativeDownloadFailure.storage }
            file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true); path = destination; metadata = value
            completionHandler(.allow)
        } catch { completionHandler(.cancel); finish(.failure(error as? NativeDownloadFailure ?? .storage)) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard !terminal else { return }
        do {
            guard !isCancelled else { throw NativeDownloadFailure.cancelled }
            guard Int64(data.count) <= maximum - received else { throw NativeDownloadFailure.capacity }
            if let length = metadata?.length { guard Int64(data.count) <= length - received else { throw NativeDownloadFailure.integrity } }
            try capacity(Int64(data.count)); guard let file else { throw NativeDownloadFailure.response }
            try file.write(contentsOf: data); digest.update(data: data); received += Int64(data.count)
            let now = Date.timeIntervalSinceReferenceDate
            if now - lastProgress >= 0.1 { lastProgress = now; let count = received, length = metadata?.length; DispatchQueue.main.async { [progress] in progress(count,length) } }
        } catch { finish(.failure(error as? NativeDownloadFailure ?? .storage)) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard !terminal else { return }
        if isCancelled { finish(.failure(.cancelled)); return }
        guard error == nil else { finish(.failure(.network)); return }
        do {
            guard let file, let path, let metadata else { throw NativeDownloadFailure.response }
            if let length = metadata.length { guard received == length else { throw NativeDownloadFailure.integrity } }
            let actual = digest.finalize().map { String(format: "%02x", $0) }.joined()
            if let expected = metadata.serverDigest { guard expected == actual else { throw NativeDownloadFailure.integrity } }
            try file.synchronize(); try file.close(); self.file = nil
            var state = stat(); guard lstat(path.path,&state) == 0, state.st_mode & S_IFMT == S_IFREG, state.st_mode & 0o7777 == 0o600,
                state.st_uid == getuid(), state.st_nlink == 1, state.st_size == received else { throw NativeDownloadFailure.storage }
            let named=try NativeDownloadCache.displayName(path,filename:metadata.filename);self.path=named
            finish(.success(NativeDownloadedFile(url:named,metadata:metadata,bytes:received,sha256:actual)))
        } catch { finish(.failure(error as? NativeDownloadFailure ?? .storage)) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil); finish(.failure(.response))
    }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(!isCancelled && challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust ? .performDefaultHandling : .cancelAuthenticationChallenge, nil)
    }
    private func finish(_ result: Result<NativeDownloadedFile, NativeDownloadFailure>) {
        guard !terminal else { return }; terminal = true
        try? file?.close(); file = nil; cookie = ""
        if case .failure = result, let path { NativeDownloadCache.discard(path) }
        lock.lock(); let transport = session; lock.unlock(); transport?.invalidateAndCancel()
        if leased { leased = false; NativeDownloadBudget.release() }
        DispatchQueue.main.async { [self] in
            if isCancelled, case .success(let file) = result { file.discard(); completion(.failure(.cancelled)) }
            else { completion(result) }
        }
    }
}
