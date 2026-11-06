import SwiftUI
import WebKit
import LocalAuthentication
import UniformTypeIdentifiers
import UIKit

@MainActor final class PanelSession: NSObject, ObservableObject, WKNavigationDelegate, WKUIDelegate, UIDocumentPickerDelegate {
    @Published var endpoint = UserDefaults.standard.string(forKey: "panelEndpoint") ?? ""
    @Published var web: WKWebView?
    @Published var status = "请输入 HTTPS 面板地址。原生层不保存密码或会话。"
    @Published var locked = false
    @Published var privacyCover = false
    @Published var error: String?
    @Published var downloadStatus = ""
    private(set) var address: PanelAddress?
    private var auth: LAContext?
    private var authAttempt: SessionCallbackTicket?
    private var upload: (([URL]?) -> Void)?
    private var uploadTicket: SessionCallbackTicket?
    private var picker: UIDocumentPickerViewController?
    private var callbacks = SessionCallbacks<[URL]>()
    private var connectionTicket: SessionCallbackTicket?
    private var pageDialog: UIAlertController?
    private var pageDialogTicket: SessionCallbackTicket?
    private var pageDialogCompletion: ((Bool) -> Void)?
    private var downloadIdentity: UUID?
    private var downloadOwner: SessionCallbackTicket?
    private var downloadTransport: ForegroundFileDownload?
    private var downloadedFile: NativeDownloadedFile?
    private var exportPicker: UIDocumentPickerViewController?
    private var exportTicket: SessionCallbackTicket?
    private weak var downloadPrivacyView: UIView?
    var hasDownload: Bool { downloadIdentity != nil }
    var canExportDownload: Bool { callbacks.interactive && downloadedFile != nil && exportPicker == nil && exportTicket == nil }

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
            config.applicationNameForUserAgent = "YunzhanMobile/1.3.3"
            let view = WKWebView(frame: .zero, configuration: config)
            view.navigationDelegate = self; view.uiDelegate = self; view.isInspectable = false
            view.allowsBackForwardNavigationGestures = true
            callbacks.start(); connectionTicket = callbacks.viewTicket; address = next; web = view; syncPrivacy()
            endpoint = next.url.absoluteString
            UserDefaults.standard.set(endpoint, forKey: "panelEndpoint")
            status = next.origin + " · 系统 TLS 验证"
            view.load(URLRequest(url: next.url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 30))
        } catch { self.error = error.localizedDescription }
    }
    func disconnect() {
        discardDownload()
        callbacks.end()
        connectionTicket = nil
        let previous = web; web = nil; address = nil
        previous?.isHidden = true; previous?.accessibilityElementsHidden = true
        previous?.stopLoading(); previous?.navigationDelegate = nil; previous?.uiDelegate = nil
        cancelPageDialog()
        auth?.invalidate(); auth = nil; authAttempt = nil
        picker?.delegate = nil; picker?.dismiss(animated: false); picker = nil
        let cancelled = upload; upload = nil; uploadTicket = nil; cancelled?(nil)
        locked = false; privacyCover = false
        status = "本地会话已清除。服务器旧会话仍按原有效期过期。"
    }
    func cover(background: Bool) {
        guard web != nil else { return }
        callbacks.cover(background: background)
        if downloadIdentity != nil && downloadedFile == nil { discardDownload(); status = "下载已停止，未完成的文件没有导出。" }
        cancelPageDialog()
        if background { auth?.invalidate(); auth = nil; authAttempt = nil }
        syncPrivacy()
    }
    func syncPrivacy() {
        locked = callbacks.locked; privacyCover = web != nil && !callbacks.interactive
        // Cover the actual UIKit view synchronously, not only its SwiftUI overlay.
        let concealed = locked || privacyCover
        web?.isHidden = concealed; web?.accessibilityElementsHidden = concealed
        downloadPrivacyView?.isHidden = concealed || !hasDownload
        downloadPrivacyView?.accessibilityElementsHidden = concealed || !hasDownload
    }
    func bindDownloadPrivacyView(_ view:UIView) { downloadPrivacyView=view;view.isHidden = !callbacks.interactive || !hasDownload;view.accessibilityElementsHidden = view.isHidden }
    func activate() { callbacks.activate(); syncPrivacy(); deliverUpload(); deliverExport() }
    private func currentWeb(_ view: WKWebView) -> Bool {
        guard view === web, let ticket = connectionTicket else { return false }
        return callbacks.ownsView(ticket)
    }
    func unlock() {
        guard locked, web != nil, auth == nil else { return }
        let context = LAContext(); var failure: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &failure) else {
            error = "请先设置设备锁屏，或退出当前会话后重新登录。"; return
        }
        guard let attempt = callbacks.beginAuthentication() else { return }
        auth = context; authAttempt = attempt
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "解锁云栈面板，保护服务器管理会话") { [weak self] success, _ in
            Task { @MainActor in
                guard let self, self.authAttempt == attempt else { return }
                self.auth = nil; self.authAttempt = nil
                _ = self.callbacks.finishAuthentication(attempt, success: success)
                self.syncPrivacy(); self.deliverUpload(); self.deliverExport()
            }
        }
    }
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard currentWeb(webView) else { decisionHandler(.cancel); return }
        guard let url = action.request.url, let address, address.allows(url) else {
            if action.targetFrame?.isMainFrame ?? true { error = "已阻止跨站或不安全跳转；面板会话不会传给外站。" }
            decisionHandler(.cancel); return
        }
        if action.shouldPerformDownload { decisionHandler(.cancel); requestDownload(url,view:webView); return }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        guard currentWeb(webView) else { decisionHandler(.cancel); return }
        guard let url = response.response.url, address?.allows(url) == true else { decisionHandler(.cancel); return }
        if let http=response.response as? HTTPURLResponse,
           http.value(forHTTPHeaderField:"Content-Disposition")?.trimmingCharacters(in:.whitespaces).lowercased().hasPrefix("attachment") == true {
            decisionHandler(.cancel);requestDownload(url,view:webView);return
        }
        guard response.canShowMIMEType else {
            error = "该下载类型暂不可用，请使用面板文件管理中的下载操作。"; decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard currentWeb(webView) else { completionHandler(.cancelAuthenticationChallenge, nil); return }
        // Never accept self-signed/expired certificates or extract credentials.
        completionHandler(.performDefaultHandling, nil)
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError failure: Error) {
        guard currentWeb(webView), (failure as NSError).code != NSURLErrorCancelled else { return }
        status = "连接失败。请检查地址、网络和可信 HTTPS 证书。"
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard currentWeb(webView), let address else { return }; status = address.origin + " · 已连接"
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        guard currentWeb(webView) else { return }
        disconnect(); error = "网页进程已退出，本地会话已清除。请重新连接并登录，不会自动恢复旧会话。"
    }
    func webView(_ webView: WKWebView, createWebViewWith config: WKWebViewConfiguration, for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        guard currentWeb(webView) else { return nil }
        if let url = action.request.url, callbacks.interactive, address?.allows(url) == true { webView.load(action.request) }
        else { error = "已阻止跨站窗口。" }; return nil
    }
    func presenter() -> UIViewController? {
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first { $0.activationState == .foregroundActive }
        var controller = scene?.windows.first { $0.isKeyWindow }?.rootViewController
        while let shown = controller?.presentedViewController { controller = shown }
        return controller
    }
    func dialog(_ message: String, view: WKWebView, origin: URL, confirm: Bool, done: @escaping (Bool) -> Void) {
        guard currentWeb(view), callbacks.interactive, pageDialog == nil, picker == nil, upload == nil, downloadIdentity == nil, exportPicker == nil,
              let owner = connectionTicket, let address, address.allows(origin), let presenter = presenter(),
              let ticket = callbacks.beginPrompt(owner) else { done(false); return }
        let alert = UIAlertController(title: "来自 " + address.origin, message: String(message.prefix(2048)), preferredStyle: .alert)
        pageDialog = alert; pageDialogTicket = ticket; pageDialogCompletion = done
        alert.addAction(UIAlertAction(title: "确认", style: .default) { [weak self, weak view] _ in
            guard let self, let view else { return }; self.finishPageDialog(ticket, owner: owner, view: view, origin: origin, accepted: true)
        })
        if confirm { alert.addAction(UIAlertAction(title: "取消", style: .cancel) { [weak self, weak view] _ in
            guard let self, let view else { return }; self.finishPageDialog(ticket, owner: owner, view: view, origin: origin, accepted: false)
        }) }
        presenter.present(alert, animated: true)
    }
    private func finishPageDialog(_ ticket: SessionCallbackTicket, owner: SessionCallbackTicket, view: WKWebView, origin: URL, accepted: Bool) {
        guard pageDialogTicket == ticket else { return }
        let completion = pageDialogCompletion, alert = pageDialog
        pageDialog = nil; pageDialogTicket = nil; pageDialogCompletion = nil
        let current = callbacks.finishPrompt(ticket)
        alert?.dismiss(animated: false)
        completion?(accepted && current && currentWeb(view) && callbacks.ownsView(owner) && address?.allows(origin) == true)
    }
    private func cancelPageDialog() {
        let completion = pageDialogCompletion, alert = pageDialog
        pageDialog = nil; pageDialogTicket = nil; pageDialogCompletion = nil; callbacks.cancelPrompt()
        alert?.dismiss(animated: false); completion?(false)
    }
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        guard currentWeb(webView), let url = frame.request.url, address?.allows(url) == true else { completionHandler(); return }
        dialog(message, view: webView, origin: url, confirm: false) { _ in completionHandler() }
    }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        guard currentWeb(webView), let url = frame.request.url, address?.allows(url) == true else { completionHandler(false); return }
        dialog(message, view: webView, origin: url, confirm: true, done: completionHandler)
    }
    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) { decisionHandler(.deny) }
    @available(iOS 18.4, *)
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        guard upload == nil, picker == nil, pageDialog == nil, downloadIdentity == nil, currentWeb(webView), let url = frame.request.url, address?.allows(url) == true,
              let presenter = presenter(), let ticket = callbacks.beginSelection() else { completionHandler(nil); return }
        upload = completionHandler; uploadTicket = ticket
        let pick = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        pick.allowsMultipleSelection = parameters.allowsMultipleSelection; pick.delegate = self
        picker = pick
        presenter.present(pick, animated: true)
    }
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        if controller === exportPicker {
            guard let ticket=exportTicket else { return };exportPicker=nil
            _ = callbacks.receiveSelection(ticket,value:Array(urls.filter(\.isFileURL).prefix(1)));deliverExport();return
        }
        guard controller === picker, let ticket = uploadTicket else { return }
        picker = nil
        let safe = Array(urls.filter(\.isFileURL).prefix(32))
        guard callbacks.receiveSelection(ticket, value: safe.isEmpty ? nil : safe) else { return }
        deliverUpload()
    }
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        if controller === exportPicker {
            guard let ticket=exportTicket else { return };exportPicker=nil
            _ = callbacks.receiveSelection(ticket,value:nil);deliverExport();return
        }
        guard controller === picker, let ticket = uploadTicket else { return }
        picker = nil
        if callbacks.receiveSelection(ticket, value: nil) { deliverUpload() }
    }
    private func deliverUpload() {
        guard upload != nil else { return }
        guard let selected = callbacks.takeSelection() else { return }
        let completion = upload; upload = nil; uploadTicket = nil
        guard let view = web, let url = view.url, address?.allows(url) == true else { completion?(nil); return }
        completion?(selected.value)
    }
    private func requestDownload(_ url:URL, view:WKWebView) {
        guard currentWeb(view),callbacks.interactive,let owner=connectionTicket,let address,address.allows(url) else { return }
        guard downloadIdentity == nil,exportPicker == nil else { error="原下载或保存仍在处理中，请先完成或取消。";return }
        dialog("下载当前面板的附件？将在应用内接收并核对，最长 5 分钟，最多 2 GiB。切到后台会停止传输；接收完成后请选择保存位置。",view:view,origin:url,confirm:true){[weak self,weak view] accepted in
            guard accepted,let self,let view,self.currentWeb(view),self.callbacks.interactive,self.callbacks.ownsView(owner),self.address==address else { return }
            let identity=UUID();self.downloadIdentity=identity;self.downloadOwner=owner;self.downloadStatus="正在准备接收附件…"
            view.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self,weak view] cookies in
                Task { @MainActor in
                    guard let self,let view,self.downloadIdentity==identity,self.currentWeb(view),self.callbacks.interactive,self.callbacks.ownsView(owner),self.address==address else { return }
                    do {
                        let cache=try FileManager.default.url(for:.cachesDirectory,in:.userDomainMask,appropriateFor:nil,create:true)
                        let directory=try NativeDownloadCache.prepare(cache),cookie=try NativeDownloadCookies.header(cookies,for:url)
                        let transfer=try ForegroundFileDownload(address:address,url:url,cookie:cookie,directory:directory,progress:{[weak self] count,total in
                            Task { @MainActor in guard let self,self.downloadIdentity==identity,self.callbacks.ownsView(owner),self.callbacks.interactive else { return };self.downloadStatus="已接收 \(count) / \(total.map(String.init) ?? "未知总大小") 字节" }
                        },completion:{[weak self] result in
                            Task { @MainActor in
                                guard let self,self.downloadIdentity==identity,self.callbacks.ownsView(owner),self.callbacks.interactive else { if case .success(let file)=result { file.discard() };return }
                                self.downloadTransport=nil
                                switch result {
                                case .success(let file):self.downloadedFile=file;self.downloadStatus="\(file.metadata.filename) · 已接收 \(file.bytes) 字节，可选择保存位置。"
                                case .failure(let failure):self.downloadIdentity=nil;self.downloadOwner=nil;self.downloadStatus="";self.error=failure.localizedDescription
                                }
                            }
                        });self.downloadTransport=transfer;self.downloadStatus="正在应用内接收附件…";transfer.start()
                    } catch { self.discardDownload();self.error=error.localizedDescription }
                }
            }
        }
    }
    func discardDownload() {
        downloadPrivacyView?.isHidden=true;downloadPrivacyView?.accessibilityElementsHidden=true
        downloadIdentity=nil;downloadOwner=nil;downloadTransport?.cancel();downloadTransport=nil
        downloadedFile?.discard();downloadedFile=nil
        exportPicker?.delegate=nil;exportPicker?.dismiss(animated:false);exportPicker=nil
        if exportTicket != nil { callbacks.cancelSelection() };exportTicket=nil;downloadStatus=""
    }
    func exportDownload() {
        guard canExportDownload,let file=downloadedFile,let owner=downloadOwner,callbacks.ownsView(owner),let presenter=presenter(),let ticket=callbacks.beginSelection() else { return }
        let pick=UIDocumentPickerViewController(forExporting:[file.url],asCopy:true);pick.delegate=self;exportPicker=pick;exportTicket=ticket
        presenter.present(pick,animated:true)
    }
    private func deliverExport() {
        guard exportTicket != nil,let file=downloadedFile,let owner=downloadOwner,callbacks.ownsView(owner),callbacks.interactive,
              let choice=callbacks.takeSelection() else { return }
        exportTicket=nil
        if let urls=choice.value,!urls.isEmpty {
            file.discard();downloadedFile=nil;downloadIdentity=nil;downloadOwner=nil;downloadStatus=""
            status="文件已交给所选文件提供方。请在目标位置确认内容和云端同步状态。"
        } else { downloadStatus="已取消保存，接收的文件仍可重新选择保存位置。" }
    }
}

struct PanelWebView: UIViewRepresentable {
    let web: WKWebView
    func makeUIView(context: Context) -> WKWebView { web }
    func updateUIView(_ view: WKWebView, context: Context) {}
}

/// Hide the native filename synchronously with the WKWebView when the app
/// becomes inactive, rather than waiting for a SwiftUI body refresh.
struct NativeDownloadControls: UIViewRepresentable {
    @ObservedObject var session: PanelSession
    func makeUIView(context:Context) -> UIStackView {
        let stack=UIStackView();stack.axis = .vertical;stack.spacing=6
        let message=UILabel();message.tag=1;message.numberOfLines=3;message.font = .preferredFont(forTextStyle:.caption1);message.adjustsFontForContentSizeCategory=true
        let buttons=UIStackView();buttons.axis = .horizontal;buttons.spacing=8;buttons.distribution = .fillEqually
        let save=UIButton(type:.system);save.tag=2;save.configuration = .tinted();save.setTitle("选择保存位置",for:.normal)
        save.addAction(UIAction{[weak session] _ in session?.exportDownload()},for:.touchUpInside)
        let cancel=UIButton(type:.system);cancel.configuration = .tinted();cancel.setTitle("取消并丢弃",for:.normal)
        cancel.addAction(UIAction{[weak session] _ in session?.discardDownload()},for:.touchUpInside)
        stack.addArrangedSubview(message);buttons.addArrangedSubview(save);buttons.addArrangedSubview(cancel);stack.addArrangedSubview(buttons)
        session.bindDownloadPrivacyView(stack);return stack
    }
    func updateUIView(_ view:UIStackView,context:Context) {
        (view.viewWithTag(1)as?UILabel)?.text=session.downloadStatus
        (view.viewWithTag(2)as?UIButton)?.isEnabled=session.canExportDownload
        session.bindDownloadPrivacyView(view)
    }
    func sizeThatFits(_ proposal:ProposedViewSize,uiView:UIStackView,context:Context) -> CGSize? {
        uiView.systemLayoutSizeFitting(CGSize(width:proposal.width ?? 320,height:UIView.layoutFittingCompressedSize.height),withHorizontalFittingPriority:.required,verticalFittingPriority:.fittingSizeLevel)
    }
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
            if session.hasDownload && !session.locked && !session.privacyCover {
                NativeDownloadControls(session:session).privacySensitive()
            }
            ZStack {
                if let web = session.web { PanelWebView(web: web).allowsHitTesting(!session.locked && !session.privacyCover).accessibilityHidden(session.locked || session.privacyCover) }
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
