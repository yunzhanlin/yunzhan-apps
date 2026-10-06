import SwiftUI
import WebKit
import LocalAuthentication
import UniformTypeIdentifiers

@MainActor final class PanelSession: NSObject, ObservableObject, WKNavigationDelegate, WKUIDelegate, UIDocumentPickerDelegate {
    @Published var endpoint = UserDefaults.standard.string(forKey: "panelEndpoint") ?? ""
    @Published var web: WKWebView?
    @Published var status = "请输入 HTTPS 面板地址。原生层不保存密码或会话。"
    @Published var locked = false
    @Published var privacyCover = false
    @Published var error: String?
    private(set) var address: PanelAddress?
    private var auth: LAContext?
    private var authAttempt: UUID?
    private var upload: (([URL]?) -> Void)?

    func connect() {
        do {
            #if DEBUG
            let debug = true
            #else
            let debug = false
            #endif
            let next = try PanelAddress(endpoint.trimmingCharacters(in: .whitespacesAndNewlines), debug: debug)
            disconnect()
            // Ephemeral data store: no management cookies/cache survive app termination.
            let config = WKWebViewConfiguration(); config.websiteDataStore = .nonPersistent()
            config.defaultWebpagePreferences.allowsContentJavaScript = true
            config.preferences.javaScriptCanOpenWindowsAutomatically = false
            let view = WKWebView(frame: .zero, configuration: config)
            view.navigationDelegate = self; view.uiDelegate = self; view.isInspectable = false
            view.customUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1 YunzhanMobile/1.3.0"
            view.allowsBackForwardNavigationGestures = true
            address = next; web = view; locked = false; privacyCover = false
            endpoint = next.url.absoluteString
            UserDefaults.standard.set(endpoint, forKey: "panelEndpoint")
            status = next.origin + " · 系统 TLS 验证"
            view.load(URLRequest(url: next.url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 30))
        } catch { self.error = error.localizedDescription }
    }
    func disconnect() {
        auth?.invalidate(); auth = nil; authAttempt = nil
        upload?(nil); upload = nil
        web?.stopLoading(); web?.navigationDelegate = nil; web?.uiDelegate = nil
        web = nil; address = nil; locked = false; privacyCover = false
        status = "本地会话已清除。服务器旧会话仍按原有效期过期。"
    }
    func cover(background: Bool) {
        guard web != nil else { return }
        privacyCover = true
        if background { locked = true }
    }
    func activate() { if !locked { privacyCover = false } }
    func unlock() {
        guard locked, web != nil, auth == nil else { return }
        let context = LAContext(); var failure: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &failure) else {
            error = "请先设置设备锁屏，或退出当前会话后重新登录。"; return
        }
        let attempt = UUID(); auth = context; authAttempt = attempt
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "解锁云栈面板，保护服务器管理会话") { [weak self] success, _ in
            Task { @MainActor in
                guard let self, self.authAttempt == attempt else { return }
                self.auth = nil; self.authAttempt = nil
                if success && self.web != nil { self.locked = false; self.privacyCover = false }
            }
        }
    }
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url, let address, address.allows(url) else {
            if action.targetFrame?.isMainFrame ?? true { error = "已阻止跨站或不安全跳转；面板会话不会传给外站。" }
            decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        guard let url = response.response.url, address?.allows(url) == true else { decisionHandler(.cancel); return }
        guard response.canShowMIMEType else {
            error = "暂不自动下载管理数据。请在可信浏览器登录面板后下载。"; decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Never accept self-signed/expired certificates or extract credentials.
        completionHandler(.performDefaultHandling, nil)
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError failure: Error) {
        guard (failure as NSError).code != NSURLErrorCancelled else { return }
        status = "连接失败。请检查地址、网络和可信 HTTPS 证书。"
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard let address else { return }; status = address.origin + " · 已连接"
    }
    func webView(_ webView: WKWebView, createWebViewWith config: WKWebViewConfiguration, for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url, !locked, address?.allows(url) == true { webView.load(action.request) }
        else { error = "已阻止跨站窗口。" }; return nil
    }
    func presenter() -> UIViewController? {
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first { $0.activationState == .foregroundActive }
        var controller = scene?.windows.first { $0.isKeyWindow }?.rootViewController
        while let shown = controller?.presentedViewController { controller = shown }
        return controller
    }
    func dialog(_ message: String, confirm: Bool, done: @escaping (Bool) -> Void) {
        guard !locked, let address, let presenter = presenter() else { done(false); return }
        let alert = UIAlertController(title: "来自 " + address.origin, message: String(message.prefix(2048)), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "确认", style: .default) { _ in done(true) })
        if confirm { alert.addAction(UIAlertAction(title: "取消", style: .cancel) { _ in done(false) }) }
        presenter.present(alert, animated: true)
    }
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        guard let url = frame.request.url, address?.allows(url) == true else { completionHandler(); return }
        dialog(message, confirm: false) { _ in completionHandler() }
    }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        guard let url = frame.request.url, address?.allows(url) == true else { completionHandler(false); return }
        dialog(message, confirm: true, done: completionHandler)
    }
    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) { decisionHandler(.deny) }
    @available(iOS 18.4, *)
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        guard !locked, let url = frame.request.url, address?.allows(url) == true, let presenter = presenter() else { completionHandler(nil); return }
        upload?(nil); upload = completionHandler
        let pick = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        pick.allowsMultipleSelection = parameters.allowsMultipleSelection; pick.delegate = self
        presenter.present(pick, animated: true)
    }
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        let safe = Array(urls.filter(\.isFileURL).prefix(32)); upload?(safe.isEmpty ? nil : safe); upload = nil
    }
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { upload?(nil); upload = nil }
}

struct PanelWebView: UIViewRepresentable {
    let web: WKWebView
    func makeUIView(context: Context) -> WKWebView { web }
    func updateUIView(_ view: WKWebView, context: Context) {}
}

struct PanelHome: View {
    @StateObject private var session = PanelSession()
    @Environment(\.scenePhase) var phase
    var body: some View {
        VStack(spacing: 12) {
            Text("云栈面板 · 安全移动端").font(.headline)
            if !session.locked {
                TextField("https://你的面板地址/安全入口/", text: $session.endpoint)
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL).textFieldStyle(.roundedBorder).disabled(session.web != nil)
                HStack {
                    Button("连接") { session.connect() }.disabled(session.web != nil)
                    Button("刷新") { session.web?.reload() }.disabled(session.web == nil)
                    Button("清除会话") { session.disconnect() }
                }.buttonStyle(.bordered)
            }
            Text(session.status).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            ZStack {
                if let web = session.web { PanelWebView(web: web).allowsHitTesting(!session.locked && !session.privacyCover) }
                else { ContentUnavailableView("连接你的云栈服务器", systemImage: "server.rack", description: Text("沿用面板登录、双重验证、网站范围和角色权限。正式包仅连接可信 HTTPS。")) }
                if session.locked || session.privacyCover {
                    VStack(spacing: 20) {
                        Image(systemName: "lock.shield.fill").font(.largeTitle)
                        Text("面板已锁定").font(.title2)
                        Button("使用设备凭据解锁") { session.unlock() }.buttonStyle(.borderedProminent)
                        Button("退出并重新登录") { session.disconnect() }
                    }.frame(maxWidth: .infinity, maxHeight: .infinity).background(.background)
                }
            }.privacySensitive()
        }.padding(.horizontal, 12).padding(.top, 8)
         .alert("云栈面板", isPresented: Binding(get: { session.error != nil }, set: { if !$0 { session.error = nil } })) { Button("知道了") { session.error = nil } } message: { Text(session.error ?? "") }
         .onChange(of: phase) { _, next in
             if next == .inactive { session.cover(background: false) }
             if next == .background { session.cover(background: true) }
             if next == .active { session.activate() }
         }
    }
}
@main struct YunzhanMobile: App { var body: some Scene { WindowGroup { PanelHome() } } }
