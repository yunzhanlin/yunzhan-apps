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
import android.webkit.RenderProcessGoneDetail;
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
    private LinearLayout root, controls, lock;
    private FrameLayout frame;
    private TextView state;
    private ProgressBar progress;
    private EditText endpoint;
    private volatile WebView web;
    private volatile PanelAddress address;
    private ValueCallback<Uri[]> files;
    private CancellationSignal authentication;
    private AlertDialog pageDialog;
    private JsResult pageDialogResult;
    private SessionCallbacks.Ticket pageDialogTicket;
    private final SessionCallbacks<Uri[]> session = new SessionCallbacks<>();
    private boolean clearing, closed;
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
        TextView title = new TextView(this); title.setText(R.string.title); title.setTextSize(21); title.setPadding(20, 14, 20, 10); root.addView(title);
        controls = new LinearLayout(this); controls.setOrientation(LinearLayout.VERTICAL); controls.setPadding(20, 0, 20, 12);
        endpoint = new EditText(this); endpoint.setSingleLine(true); endpoint.setHint(R.string.endpoint_hint); endpoint.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        endpoint.setText(getPreferences(MODE_PRIVATE).getString("endpoint", "")); controls.addView(endpoint);
        LinearLayout buttons = new LinearLayout(this);
        Button connect = button(R.string.connect, () -> connect(endpoint.getText().toString().trim()));
        Button clear = button(R.string.clear_session, this::disconnect);
        Button refresh = button(R.string.refresh, () -> { if (web != null && session.interactive()) web.reload(); });
        buttons.addView(connect); buttons.addView(refresh); buttons.addView(clear); controls.addView(buttons); root.addView(controls);
        // Android17 requires a separate OS grant for LAN endpoints. This is an
        // explicit native action, not a webpage permission or auto-reconnect.
        // There is no permission-result callback that could act on a new session.
        if (android.os.Build.VERSION.SDK_INT >= 37) controls.addView(button(R.string.local_network_permission, this::allowLocalNetwork));
        state = new TextView(this); state.setText(R.string.privacy_status); state.setPadding(20, 0, 20, 10); root.addView(state);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal); progress.setMax(100); progress.setVisibility(View.GONE); root.addView(progress);
        frame = new FrameLayout(this); root.addView(frame, new LinearLayout.LayoutParams(-1, 0, 1));
        lock = new LinearLayout(this); lock.setOrientation(LinearLayout.VERTICAL); lock.setBackgroundColor(Color.WHITE); lock.setGravity(android.view.Gravity.CENTER);
        TextView privacy = new TextView(this); privacy.setText(R.string.locked_message); privacy.setTextSize(19); privacy.setGravity(android.view.Gravity.CENTER); lock.addView(privacy);
        lock.addView(button(R.string.unlock, this::unlock)); lock.addView(button(R.string.logout, this::disconnect));
        setContentView(root);
        // Process restart requires fresh web login. No persisted native password or session.
        clearLocal(null);
        if (android.os.Build.VERSION.SDK_INT >= 33) getOnBackInvokedDispatcher().registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, this::goBack);
    }
    private void goBack() { if (web != null && session.interactive() && web.canGoBack()) web.goBack(); else if (web != null) disconnect(); else finish(); }
    // API 33+ uses the registered native dispatcher above; only API 30-32 calls this fallback.
    @android.annotation.SuppressLint("GestureBackNavigation")
    @Override public void onBackPressed() { goBack(); }
    private Button button(int text, Runnable action) { Button b = new Button(this); b.setText(text); b.setOnClickListener(v -> action.run()); return b; }
    private void tell(int text) { new AlertDialog.Builder(this).setTitle(R.string.app_name).setMessage(text).setPositiveButton(R.string.understood, null).show(); }
    private void allowLocalNetwork() {
        if (closed || isFinishing() || android.os.Build.VERSION.SDK_INT < 37 || (web != null && !session.interactive())) return;
        String permission = "android.permission.ACCESS_LOCAL_NETWORK";
        if (checkSelfPermission(permission) == android.content.pm.PackageManager.PERMISSION_GRANTED) { tell(R.string.local_network_granted); return; }
        requestPermissions(new String[]{permission}, 512);
    }
    // UI-thread callbacks must belong to this exact WebView and connection,
    // not merely an equal URL or a new session at the same origin.
    private boolean currentView(WebView view, SessionCallbacks.Ticket ticket) { return view == web && session.ownsView(ticket); }
    // The Vue panel needs JavaScript. This narrow warning acknowledgement is
    // not a native bridge or an XSS exemption: release URLs require HTTPS,
    // certificate errors cancel, file/content access and mixed content are
    // disabled, and the panel must retain its strict self-only CSP. WebView
    // interception is not a firewall for every redirect/blob/WebSocket path.
    @android.annotation.SuppressLint("SetJavaScriptEnabled")
    private void configureWebSettings(WebView view) {
        WebSettings settings = view.getSettings(); settings.setJavaScriptEnabled(true); settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false); settings.setAllowContentAccess(false); settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setGeolocationEnabled(false); settings.setSafeBrowsingEnabled(true); settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setMediaPlaybackRequiresUserGesture(true); settings.setSupportMultipleWindows(false); settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setUserAgentString(settings.getUserAgentString() + " YunzhanMobile/" + BuildConfig.VERSION_NAME);
        CookieManager.getInstance().setAcceptCookie(true); CookieManager.getInstance().setAcceptThirdPartyCookies(view, false);
    }
    private void connect(String raw) {
        final PanelAddress target;
        try { target = PanelAddress.parse(raw, BuildConfig.DEBUG); } catch (IllegalArgumentException e) { tell(R.string.invalid_panel_address); return; }
        if (clearing) { tell(R.string.clearing_old_session); return; }
        destroyWeb(); address = null;
        clearLocal(() -> {
            if (closed) return;
            address = target; session.start();
            final SessionCallbacks.Ticket viewTicket = session.viewTicket();
            getPreferences(MODE_PRIVATE).edit().putString("endpoint", target.uri.toString()).apply();
            endpoint.setText(target.uri.toString()); endpoint.setEnabled(false);
            state.setText(getString(R.string.connection_status, target.displayOrigin(), getString(BuildConfig.DEBUG ? R.string.connection_qa : R.string.connection_system_tls)));
            web = new WebView(this);
            final WebView connected = web;
            configureWebSettings(connected);
            // No JavaScript/native bridge. Check navigation and the initial
            // HTTP resource URL; the server CSP covers additional web paths.
            web.setWebViewClient(new WebViewClient() {
                @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                    if (!currentView(v, viewTicket)) return true;
                    if (address != null && address.allows(r.getUrl().toString())) return false;
                    if (r.isForMainFrame()) tell(R.string.navigation_blocked);
                    return true;
                }
                @Override public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest r) {
                    PanelAddress current = address;
                    // This callback is off the UI thread. Read only volatile
                    // connection identity; do not call main-thread session or
                    // WebView state APIs here.
                    if (v == web && current == target && current.allows(r.getUrl().toString())) return null;
                    return new WebResourceResponse("text/plain", "UTF-8", 403, "Origin blocked", java.util.Map.of("Cache-Control", "no-store"), new ByteArrayInputStream(new byte[0]));
                }
                @Override public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError error) {
                    handler.cancel(); if (currentView(v, viewTicket)) state.setText(R.string.tls_failed);
                }
                @Override public void onReceivedError(WebView v, WebResourceRequest r, WebResourceError error) {
                    if (currentView(v, viewTicket) && r.isForMainFrame()) state.setText(R.string.connection_failed);
                }
                @Override public boolean onRenderProcessGone(WebView v, RenderProcessGoneDetail detail) {
                    if (currentView(v, viewTicket)) { disconnect(); tell(R.string.renderer_failed); }
                    return true;
                }
            });
            web.setWebChromeClient(new WebChromeClient() {
                @Override public void onProgressChanged(WebView v, int value) { if (currentView(v, viewTicket)) { progress.setProgress(value); progress.setVisibility(value == 100 ? View.GONE : View.VISIBLE); } }
                @Override public void onPermissionRequest(PermissionRequest request) { request.deny(); }
                @Override public boolean onJsAlert(WebView v, String url, String message, JsResult result) { return jsDialog(v, viewTicket, url, message, result, false); }
                @Override public boolean onJsConfirm(WebView v, String url, String message, JsResult result) { return jsDialog(v, viewTicket, url, message, result, true); }
                @Override public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> callback, FileChooserParams params) {
                    if (files != null || !currentView(v, viewTicket) || !session.interactive() || address == null || !address.allows(v.getUrl()) || params.getMode() == FileChooserParams.MODE_SAVE) { callback.onReceiveValue(null); return true; }
                    SessionCallbacks.Ticket ticket = session.beginSelection();
                    if (ticket == null) { callback.onReceiveValue(null); return true; }
                    files = callback;
                    Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT); pick.setType("*/*"); pick.addCategory(Intent.CATEGORY_OPENABLE);
                    pick.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE);
                    try { startActivityForResult(pick, ticket.requestCode); } catch (RuntimeException e) { cancelFiles(); tell(R.string.file_picker_unavailable); }
                    return true;
                }
            });
            web.setDownloadListener((url, userAgent, contentDisposition, mimeType, bytes) -> { if (currentView(connected, viewTicket) && session.interactive()) tell(R.string.download_notice); });
            frame.removeAllViews(); frame.addView(web, new FrameLayout.LayoutParams(-1, -1));
            if (session.locked()) { frame.addView(lock, new FrameLayout.LayoutParams(-1, -1)); controls.setVisibility(View.GONE); web.onPause(); web.pauseTimers(); }
            web.loadUrl(target.uri.toString());
        });
    }
    private boolean jsDialog(WebView view, SessionCallbacks.Ticket ticket, String url, String message, JsResult result, boolean confirm) {
        if (!currentView(view, ticket) || !session.interactive() || address == null || !address.allows(url)) { result.cancel(); return true; }
        if (pageDialogResult != null) { if (pageDialogResult != result) result.cancel(); return true; }
        final SessionCallbacks.Ticket prompt = session.beginPrompt(ticket);
        if (prompt == null) { result.cancel(); return true; }
        pageDialogResult = result; pageDialogTicket = prompt;
        AlertDialog.Builder dialog = new AlertDialog.Builder(this).setTitle(getString(R.string.page_dialog_title, address.displayOrigin())).setMessage(message.length() > 2048 ? message.substring(0, 2048) : message)
            .setPositiveButton(R.string.confirm, (d, w) -> finishPageDialog(view, ticket, prompt, url, result, true))
            .setOnCancelListener(d -> finishPageDialog(view, ticket, prompt, url, result, false));
        if (confirm) dialog.setNegativeButton(R.string.cancel, (d, w) -> finishPageDialog(view, ticket, prompt, url, result, false));
        pageDialog = dialog.create();
        pageDialog.setOnDismissListener(d -> finishPageDialog(view, ticket, prompt, url, result, false));
        pageDialog.show(); return true;
    }
    private void finishPageDialog(WebView view, SessionCallbacks.Ticket owner, SessionCallbacks.Ticket prompt, String url, JsResult result, boolean accepted) {
        if (pageDialogResult != result || pageDialogTicket != prompt) return;
        AlertDialog dialog = pageDialog; pageDialog = null; pageDialogResult = null; pageDialogTicket = null;
        boolean current = session.finishPrompt(prompt);
        if (accepted && current && currentView(view, owner) && address != null && address.allows(url)) result.confirm();
        else result.cancel();
        if (dialog != null) dialog.dismiss();
    }
    private void cancelPageDialog() {
        AlertDialog dialog = pageDialog; JsResult result = pageDialogResult;
        pageDialog = null; pageDialogResult = null; pageDialogTicket = null; session.cancelPrompt();
        if (dialog != null) dialog.dismiss();
        if (result != null) result.cancel();
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (files == null || !session.awaitingSelection(request)) return;
        java.util.LinkedHashSet<Uri> selected = new java.util.LinkedHashSet<>();
        if (result == RESULT_OK && data != null) {
            if (data.getData() != null && "content".equals(data.getData().getScheme())) selected.add(data.getData());
            if (data.getClipData() != null) for (int i = 0; i < Math.min(32, data.getClipData().getItemCount()) && selected.size() < 32; i++) {
                Uri uri = data.getClipData().getItemAt(i).getUri(); if ("content".equals(uri.getScheme())) selected.add(uri);
            }
        }
        if (!session.receiveSelection(request, selected.isEmpty() ? null : selected.toArray(new Uri[0]))) return;
        deliverFiles();
    }
    private void cancelFiles() {
        session.cancelSelection(); ValueCallback<Uri[]> callback = files; files = null;
        if (callback != null) callback.onReceiveValue(null);
    }
    private void deliverFiles() {
        SessionCallbacks.Selection<Uri[]> selected = session.takeSelection();
        if (selected == null || files == null) return;
        ValueCallback<Uri[]> callback = files; files = null;
        if (web == null || address == null || !address.allows(web.getUrl())) callback.onReceiveValue(null);
        else callback.onReceiveValue(selected.value);
    }
    @Override protected void onResume() { super.onResume(); session.foreground(true); }
    @Override protected void onPause() {
        super.onPause();
        session.foreground(false);
        cancelPageDialog();
        if (authentication != null) authentication.cancel(); authentication = null;
        if (web == null) return;
        web.onPause(); web.pauseTimers();
        if (lock.getParent() == null) frame.addView(lock, new FrameLayout.LayoutParams(-1, -1));
        controls.setVisibility(View.GONE);
    }
    private void unlock() {
        if (!session.locked() || web == null || authentication != null) return;
        KeyguardManager guard = (KeyguardManager)getSystemService(KEYGUARD_SERVICE);
        if (!guard.isDeviceSecure()) { tell(R.string.device_security_required); return; }
        final SessionCallbacks.Ticket ticket = session.beginAuthentication();
        if (ticket == null) return;
        final CancellationSignal signal = new CancellationSignal(); authentication = signal;
        BiometricPrompt prompt = new BiometricPrompt.Builder(this).setTitle(getString(R.string.unlock_title)).setSubtitle(getString(R.string.unlock_subtitle))
            .setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG | android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL).build();
        prompt.authenticate(signal, getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
            @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                if (authentication != signal || closed || isFinishing() || !session.finishAuthentication(ticket, true)) return;
                authentication = null;
                if (web == null) return;
                frame.removeView(lock); controls.setVisibility(View.VISIBLE); web.onResume(); web.resumeTimers(); deliverFiles();
            }
            @Override public void onAuthenticationError(int code, CharSequence text) {
                if (authentication != signal) return;
                authentication = null; session.finishAuthentication(ticket, false); state.setText(R.string.still_locked);
            }
        });
    }
    private void disconnect() {
        if (authentication != null) authentication.cancel(); authentication = null;
        destroyWeb(); address = null; endpoint.setEnabled(true); controls.setVisibility(View.VISIBLE);
        state.setText(R.string.clearing_data);
        clearLocal(() -> { if (!closed) state.setText(R.string.session_cleared); });
    }
    private void clearLocal(Runnable done) {
        if (!resetting.compareAndSet(false, true)) return;
        clearing = true; WebStorage.getInstance().deleteAllData();
        CookieManager.getInstance().removeAllCookies(success -> {
            CookieManager.getInstance().flush(); clearing = false; resetting.set(false); if (done != null) done.run();
        });
    }
    private void destroyWeb() {
        session.end();
        cancelPageDialog();
        if (authentication != null) authentication.cancel(); authentication = null;
        cancelFiles();
        if (web != null) { web.stopLoading(); web.resumeTimers(); web.clearCache(true); web.clearHistory(); frame.removeAllViews(); web.destroy(); web = null; }
        progress.setVisibility(View.GONE);
    }
    @Override protected void onDestroy() { closed = true; if (authentication != null) authentication.cancel(); destroyWeb(); clearLocal(null); super.onDestroy(); }
}
