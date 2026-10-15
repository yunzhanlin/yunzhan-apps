package icu.yunzhan.panel;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.hardware.biometrics.BiometricPrompt;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.view.View;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebStorage;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import java.io.ByteArrayInputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/** Native connection/privacy controls; the authenticated panel supplies business UI. */
public final class PanelActivity extends Activity {
    private static final int FILE_PICKER = 42;
    private LinearLayout root, controls, lock;
    private FrameLayout frame;
    private TextView state;
    private ProgressBar progress;
    private EditText endpoint;
    private WebView web;
    private volatile PanelAddress address;
    private ValueCallback<Uri[]> files;
    private CancellationSignal authentication;
    private boolean locked, clearing, closed;
    private final AtomicBoolean resetting = new AtomicBoolean(false);

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        // Never expose panel data in recents, screenshots, recording or Android backups.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WebView.setWebContentsDebuggingEnabled(false);
        root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setBackgroundColor(Color.WHITE);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets safe = insets.getInsets(android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.displayCutout());
            v.setPadding(safe.left, safe.top, safe.right, safe.bottom); return insets;
        });
        TextView title = new TextView(this); title.setText("云栈面板 · 安全移动端"); title.setTextSize(21); title.setPadding(20, 14, 20, 10); root.addView(title);
        controls = new LinearLayout(this); controls.setOrientation(LinearLayout.VERTICAL); controls.setPadding(20, 0, 20, 12);
        endpoint = new EditText(this); endpoint.setSingleLine(true); endpoint.setHint("https://你的面板地址/安全入口/"); endpoint.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        endpoint.setText(getPreferences(MODE_PRIVATE).getString("endpoint", "")); controls.addView(endpoint);
        LinearLayout buttons = new LinearLayout(this);
        Button connect = button("连接", () -> connect(endpoint.getText().toString().trim()));
        Button clear = button("清除会话", this::disconnect);
        Button refresh = button("刷新", () -> { if (web != null && !locked) web.reload(); });
        buttons.addView(connect); buttons.addView(refresh); buttons.addView(clear); controls.addView(buttons); root.addView(controls);
        state = new TextView(this); state.setText("正式包仅支持 HTTPS。密码由面板登录页处理，不写入原生存储。"); state.setPadding(20, 0, 20, 10); root.addView(state);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal); progress.setMax(100); progress.setVisibility(View.GONE); root.addView(progress);
        frame = new FrameLayout(this); root.addView(frame, new LinearLayout.LayoutParams(-1, 0, 1));
        lock = new LinearLayout(this); lock.setOrientation(LinearLayout.VERTICAL); lock.setBackgroundColor(Color.WHITE); lock.setGravity(android.view.Gravity.CENTER);
        TextView privacy = new TextView(this); privacy.setText("面板已锁定\n使用设备锁屏或生物识别解锁"); privacy.setTextSize(19); privacy.setGravity(android.view.Gravity.CENTER); lock.addView(privacy);
        lock.addView(button("解锁面板", this::unlock)); lock.addView(button("退出并重新登录", this::disconnect));
        setContentView(root);
        // Process restart requires fresh web login. No persisted native password or session.
        clearLocal(null);
        if (android.os.Build.VERSION.SDK_INT >= 33) getOnBackInvokedDispatcher().registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, this::goBack);
    }
    private void goBack() { if (web != null && !locked && web.canGoBack()) web.goBack(); else if (web != null) disconnect(); else finish(); }
    // API 33+ uses the registered native dispatcher above; only API 30-32 calls this fallback.
    @android.annotation.SuppressLint("GestureBackNavigation")
    @Override public void onBackPressed() { goBack(); }
    private Button button(String text, Runnable action) { Button b = new Button(this); b.setText(text); b.setOnClickListener(v -> action.run()); return b; }
    private void tell(String text) { new AlertDialog.Builder(this).setTitle("云栈面板").setMessage(text).setPositiveButton("知道了", null).show(); }
    private void connect(String raw) {
        final PanelAddress target;
        try { target = PanelAddress.parse(raw, BuildConfig.DEBUG); } catch (IllegalArgumentException e) { tell(e.getMessage()); return; }
        if (clearing) { tell("正在清除旧会话，请稍后重试。"); return; }
        destroyWeb(); address = null;
        clearLocal(() -> {
            if (closed) return;
            address = target; locked = false;
            getPreferences(MODE_PRIVATE).edit().putString("endpoint", target.uri.toString()).apply();
            endpoint.setText(target.uri.toString()); endpoint.setEnabled(false);
            state.setText(target.displayOrigin() + (BuildConfig.DEBUG ? " · QA 测试包" : " · 系统 TLS 验证"));
            web = new WebView(this);
            WebSettings settings = web.getSettings(); settings.setJavaScriptEnabled(true); settings.setDomStorageEnabled(true);
            settings.setAllowFileAccess(false); settings.setAllowContentAccess(false); settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
            settings.setGeolocationEnabled(false); settings.setSafeBrowsingEnabled(true); settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
            settings.setMediaPlaybackRequiresUserGesture(true); settings.setSupportMultipleWindows(false);
            settings.setUserAgentString(settings.getUserAgentString() + " YunzhanMobile/1.3.0");
            CookieManager.getInstance().setAcceptCookie(true); CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);
            // No JavaScript/native bridge. Navigation and every HTTP subresource stay at one exact origin.
            web.setWebViewClient(new WebViewClient() {
                @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                    if (address != null && address.allows(r.getUrl().toString())) return false;
                    if (r.isForMainFrame()) tell("已阻止跳转到其他地址。请在外部浏览器单独访问，面板会话不会传给外站。");
                    return true;
                }
                @Override public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest r) {
                    PanelAddress current = address;
                    if (current != null && current.allows(r.getUrl().toString())) return null;
                    return new WebResourceResponse("text/plain", "UTF-8", 403, "Origin blocked", java.util.Map.of("Cache-Control", "no-store"), new ByteArrayInputStream(new byte[0]));
                }
                @Override public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError error) {
                    handler.cancel(); state.setText("证书校验失败，未继续连接。请为面板配置可信 HTTPS 证书。");
                }
                @Override public void onReceivedError(WebView v, WebResourceRequest r, WebResourceError error) {
                    if (r.isForMainFrame()) state.setText("连接失败。检查面板地址、网络和证书后重试。");
                }
            });
            web.setWebChromeClient(new WebChromeClient() {
                @Override public void onProgressChanged(WebView v, int value) { progress.setProgress(value); progress.setVisibility(value == 100 ? View.GONE : View.VISIBLE); }
                @Override public void onPermissionRequest(PermissionRequest request) { request.deny(); }
                @Override public boolean onJsAlert(WebView v, String url, String message, JsResult result) { return jsDialog(url, message, result, false); }
                @Override public boolean onJsConfirm(WebView v, String url, String message, JsResult result) { return jsDialog(url, message, result, true); }
                @Override public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> callback, FileChooserParams params) {
                    if (files != null) files.onReceiveValue(null);
                    if (locked || address == null || !address.allows(v.getUrl())) { callback.onReceiveValue(null); return true; }
                    files = callback;
                    Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT); pick.setType("*/*"); pick.addCategory(Intent.CATEGORY_OPENABLE);
                    pick.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE);
                    try { startActivityForResult(pick, FILE_PICKER); } catch (RuntimeException e) { files.onReceiveValue(null); files = null; tell("文件选择器不可用。"); }
                    return true;
                }
            });
            web.setDownloadListener((url, userAgent, contentDisposition, mimeType, bytes) -> tell("暂不自动下载管理数据。请在可信浏览器登录该面板后下载，应用不会向系统下载服务传递会话。"));
            frame.removeAllViews(); frame.addView(web, new FrameLayout.LayoutParams(-1, -1)); web.loadUrl(target.uri.toString());
        });
    }
    private boolean jsDialog(String url, String message, JsResult result, boolean confirm) {
        if (locked || address == null || !address.allows(url)) { result.cancel(); return true; }
        AlertDialog.Builder dialog = new AlertDialog.Builder(this).setTitle("来自 " + address.displayOrigin()).setMessage(message.length() > 2048 ? message.substring(0, 2048) : message).setPositiveButton("确认", (d, w) -> result.confirm()).setOnCancelListener(d -> result.cancel());
        if (confirm) dialog.setNegativeButton("取消", (d, w) -> result.cancel()); dialog.show(); return true;
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != FILE_PICKER || files == null) return;
        java.util.ArrayList<Uri> selected = new java.util.ArrayList<>();
        if (result == RESULT_OK && data != null) {
            if (data.getData() != null && "content".equals(data.getData().getScheme())) selected.add(data.getData());
            if (data.getClipData() != null) for (int i = 0; i < Math.min(32, data.getClipData().getItemCount()); i++) {
                Uri uri = data.getClipData().getItemAt(i).getUri(); if ("content".equals(uri.getScheme())) selected.add(uri);
            }
        }
        files.onReceiveValue(selected.isEmpty() ? null : selected.toArray(new Uri[0])); files = null;
    }
    @Override protected void onPause() {
        super.onPause();
        if (web == null) return;
        locked = true; web.onPause(); web.pauseTimers();
        if (lock.getParent() == null) frame.addView(lock, new FrameLayout.LayoutParams(-1, -1));
        controls.setVisibility(View.GONE);
    }
    private void unlock() {
        if (!locked || web == null || authentication != null) return;
        KeyguardManager guard = (KeyguardManager)getSystemService(KEYGUARD_SERVICE);
        if (!guard.isDeviceSecure()) { tell("设备未设置安全锁屏。请退出当前会话，或先在系统设置中启用锁屏后解锁。"); return; }
        authentication = new CancellationSignal();
        BiometricPrompt prompt = new BiometricPrompt.Builder(this).setTitle("解锁云栈面板").setSubtitle("使用设备生物识别或锁屏凭据")
            .setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG | android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL).build();
        prompt.authenticate(authentication, getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
            @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                authentication = null;
                if (web == null || isFinishing()) return;
                locked = false; frame.removeView(lock); controls.setVisibility(View.VISIBLE); web.onResume(); web.resumeTimers();
            }
            @Override public void onAuthenticationError(int code, CharSequence text) { authentication = null; state.setText("仍处于锁定状态，请解锁或退出会话。"); }
        });
    }
    private void disconnect() {
        if (authentication != null) authentication.cancel(); authentication = null;
        destroyWeb(); address = null; locked = false; endpoint.setEnabled(true); controls.setVisibility(View.VISIBLE);
        state.setText("正在清除 Cookie、网页存储与缓存…");
        clearLocal(() -> { if (!closed) state.setText("会话已清除；再次连接需要面板登录。服务器旧会话仍按原有效期过期。"); });
    }
    private void clearLocal(Runnable done) {
        if (!resetting.compareAndSet(false, true)) return;
        clearing = true; WebStorage.getInstance().deleteAllData();
        CookieManager.getInstance().removeAllCookies(success -> {
            CookieManager.getInstance().flush(); clearing = false; resetting.set(false); if (done != null) done.run();
        });
    }
    private void destroyWeb() {
        if (files != null) files.onReceiveValue(null); files = null;
        if (web != null) { web.stopLoading(); web.resumeTimers(); web.clearCache(true); web.clearHistory(); frame.removeAllViews(); web.destroy(); web = null; }
        progress.setVisibility(View.GONE);
    }
    @Override protected void onDestroy() { closed = true; if (authentication != null) authentication.cancel(); destroyWeb(); clearLocal(null); super.onDestroy(); }
}
