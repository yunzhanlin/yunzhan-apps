package icu.yunzhan.panel;

import androidx.activity.ComponentActivity;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/** Native connection/privacy controls; the authenticated panel supplies business UI. */
public final class PanelActivity extends ComponentActivity {
    private LinearLayout root, controls, lock, downloadControls;
    private FrameLayout frame;
    private TextView state;
    private ProgressBar progress;
    private EditText endpoint;
    private volatile WebView web;
    private volatile PanelAddress address;
    private ValueCallback<Uri[]> files;
    private SessionCallbacks.Ticket uploadSelection;
    private ActivityResultLauncher<Intent> uploadLauncher, exportLauncher;
    private CancellationSignal authentication;
    private AlertDialog pageDialog;
    private JsResult pageDialogResult;
    private SessionCallbacks.Ticket pageDialogTicket;
    private AlertDialog downloadDialog;
    private SessionCallbacks.Ticket downloadPrompt, downloadOwner, downloadSelection;
    private ForegroundDownload downloading;
    private ForegroundDownload.Result downloaded;
    private NativeFileExport exporting;
    private UUID downloadIdentity;
    private Button saveDownload;
    private TextView downloadState;
    private final SessionCallbacks<Uri[]> session = new SessionCallbacks<>();
    private boolean clearing, closed, webRuntimeUnavailable;
    private final AtomicBoolean resetting = new AtomicBoolean(false);

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        // Never expose panel data in recents, screenshots, recording or Android backups.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        try { WebView.setWebContentsDebuggingEnabled(false); }
        catch (RuntimeException unavailable) { webRuntimeUnavailable = true; }
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
        downloadControls = new LinearLayout(this); downloadControls.setOrientation(LinearLayout.VERTICAL); downloadControls.setPadding(20,0,20,8);
        downloadState = new TextView(this); downloadControls.addView(downloadState);
        LinearLayout transferButtons = new LinearLayout(this); saveDownload = button(R.string.download_save,this::chooseDownloadDestination); saveDownload.setEnabled(false);
        transferButtons.addView(saveDownload); transferButtons.addView(button(R.string.download_cancel,()->discardDownload(true)));
        downloadControls.addView(transferButtons); downloadControls.setVisibility(View.GONE); root.addView(downloadControls);
        frame = new FrameLayout(this); root.addView(frame, new LinearLayout.LayoutParams(-1, 0, 1));
        lock = new LinearLayout(this); lock.setOrientation(LinearLayout.VERTICAL); lock.setBackgroundColor(Color.WHITE); lock.setGravity(android.view.Gravity.CENTER);
        TextView privacy = new TextView(this); privacy.setText(R.string.locked_message); privacy.setTextSize(19); privacy.setGravity(android.view.Gravity.CENTER); lock.addView(privacy);
        lock.addView(button(R.string.unlock, this::unlock)); lock.addView(button(R.string.logout, this::disconnect));
        setContentView(root);
        // Process restart requires fresh web login. No persisted native password or session.
        if (webRuntimeUnavailable) state.setText(R.string.webview_update_required);
        else clearLocal(null);
        getOnBackPressedDispatcher().addCallback(this,new OnBackPressedCallback(true){@Override public void handleOnBackPressed(){goBack();}});
    }
    private void goBack() { if (web != null && session.interactive() && web.canGoBack()) web.goBack(); else if (web != null) disconnect(); else finish(); }
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
        if (webRuntimeUnavailable) { tell(R.string.webview_update_required); return; }
        // API30's original default image still ships Chromium83. The OS API
        // level does not establish compatibility with the panel's JS build.
        // Refuse before networking or replacing an existing connection.
        final boolean compatible;
        try {
            android.content.pm.PackageInfo provider = WebView.getCurrentWebViewPackage();
            compatible = provider != null && supportsWebViewVersion(provider.versionName);
        } catch (RuntimeException unavailable) { tell(R.string.webview_update_required); return; }
        if (!compatible) { tell(R.string.webview_update_required); return; }
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
                    if (files != null || downloadIdentity != null || !currentView(v, viewTicket) || !session.interactive() || address == null || !address.allows(v.getUrl()) || params.getMode() == FileChooserParams.MODE_SAVE) { callback.onReceiveValue(null); return true; }
                    SessionCallbacks.Ticket ticket = session.beginSelection();
                    if (ticket == null) { callback.onReceiveValue(null); return true; }
                    files = callback;uploadSelection=ticket;
                    Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT); pick.setType("*/*"); pick.addCategory(Intent.CATEGORY_OPENABLE);
                    pick.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE);
                    try {
                        // A new registry key for every launch. Restored OS
                        // results keep their old key and cannot enter a new
                        // Activity's connection even if its sequence resets.
                        uploadLauncher=getActivityResultRegistry().register("upload-"+UUID.randomUUID(),new ActivityResultContracts.StartActivityForResult(),result->{
                            if(uploadSelection!=ticket||files!=callback||!currentView(v,viewTicket)||!session.awaitingSelection(ticket.requestCode))return;
                            ActivityResultLauncher<Intent> completed=uploadLauncher;uploadLauncher=null;if(completed!=null)completed.unregister();
                            if(session.receiveSelection(ticket.requestCode,selectedUris(result.getResultCode(),result.getData())))deliverFiles();
                        });uploadLauncher.launch(pick);
                    } catch (RuntimeException e) { cancelFiles(); tell(R.string.file_picker_unavailable); }
                    return true;
                }
            });
            web.setDownloadListener((url, userAgent, contentDisposition, mimeType, bytes) -> requestDownload(connected,viewTicket,url,userAgent,contentDisposition,mimeType,bytes));
            frame.removeAllViews(); frame.addView(web, new FrameLayout.LayoutParams(-1, -1));
            if (session.locked()) coverWeb();
            web.loadUrl(target.uri.toString());
        });
    }
    // Compatibility only, not a security-patch or certificate assessment.
    static boolean supportsWebViewVersion(String version) {
        if (version == null || !version.matches("[1-9][0-9]{1,3}(\\.[0-9]{1,9}){3}")) return false;
        int major = Integer.parseInt(version.substring(0, version.indexOf('.')));
        return major >= 111;
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
    private Path downloadDirectory() throws IOException {
        return DownloadCache.prepare(getCacheDir().toPath());
    }
    private void requestDownload(WebView view, SessionCallbacks.Ticket owner, String url, String agent, String disposition, String mime, long length) {
        if(!currentView(view,owner)||!session.interactive())return;
        if(address==null||!address.allows(url)){tell(url!=null&&url.startsWith("blob:")?R.string.download_notice:R.string.download_origin_refused);return;}
        if(downloading!=null||downloaded!=null||exporting!=null||downloadDialog!=null||files!=null||downloadSelection!=null||pageDialog!=null){tell(R.string.download_busy);return;}
        final DownloadMetadata metadata;
        try{metadata=new DownloadMetadata(disposition,mime,length<0?null:Long.toString(length),null,null);if(length>ForegroundDownload.MAX_BYTES)throw new IllegalArgumentException("capacity");}
        catch(IllegalArgumentException failure){tell(R.string.download_refused);return;}
        final SessionCallbacks.Ticket ticket=session.beginPrompt(owner);if(ticket==null)return;downloadPrompt=ticket;
        downloadDialog=new AlertDialog.Builder(this).setTitle(R.string.download_title).setMessage(getString(R.string.download_confirmation,metadata.filename,address.displayOrigin()))
            .setPositiveButton(R.string.confirm,(d,w)->finishDownloadPrompt(view,owner,ticket,url,agent,true))
            .setNegativeButton(R.string.cancel,(d,w)->finishDownloadPrompt(view,owner,ticket,url,agent,false))
            .setOnCancelListener(d->finishDownloadPrompt(view,owner,ticket,url,agent,false)).create();
        downloadDialog.setOnDismissListener(d->finishDownloadPrompt(view,owner,ticket,url,agent,false));downloadDialog.show();
    }
    private void finishDownloadPrompt(WebView view, SessionCallbacks.Ticket owner, SessionCallbacks.Ticket prompt, String url, String agent, boolean accepted) {
        if(downloadPrompt!=prompt)return;AlertDialog dialog=downloadDialog;downloadDialog=null;downloadPrompt=null;
        boolean allowed=session.finishPrompt(prompt)&&accepted&&currentView(view,owner)&&session.interactive()&&address!=null&&address.allows(url);
        if(dialog!=null)dialog.dismiss();if(!allowed)return;
        UUID identity=UUID.randomUUID();downloadIdentity=identity;downloadOwner=owner;
        try{
            ForegroundDownload operation=new ForegroundDownload(address,url,CookieManager.getInstance().getCookie(url),agent,downloadDirectory(),getMainExecutor(),new ForegroundDownload.Listener(){
                private boolean current(){return identity.equals(downloadIdentity)&&currentView(view,owner)&&session.interactive();}
                public void progress(long received,long expected){if(current())downloadState.setText(getString(R.string.download_progress,Long.toString(received),expected<0?getString(R.string.download_unknown_size):Long.toString(expected)));}
                public void complete(ForegroundDownload.Result file){
                    if(!current()||downloading==null||downloading.cancelled()){removePrivateDownload(file);return;}
                    downloading=null;downloaded=file;saveDownload.setEnabled(true);downloadState.setText(getString(R.string.download_ready,file.filename,Long.toString(file.bytes)));
                }
                public void failed(ForegroundDownload.Failure reason){if(!identity.equals(downloadIdentity))return;downloading=null;downloadIdentity=null;downloadOwner=null;downloadControls.setVisibility(View.GONE);state.setText(reason==ForegroundDownload.Failure.CANCELLED?R.string.download_cancelled:reason==ForegroundDownload.Failure.BUSY?R.string.download_busy:R.string.download_failed);}
            });
            downloading=operation;saveDownload.setEnabled(false);downloadState.setText(R.string.download_receiving);downloadControls.setVisibility(View.VISIBLE);operation.start();
        }catch(IOException|RuntimeException failure){discardDownload(false);tell(R.string.download_failed);}
    }
    private void cancelDownloadPrompt() {
        if(downloadDialog==null)return;AlertDialog dialog=downloadDialog;downloadDialog=null;downloadPrompt=null;session.cancelPrompt();dialog.dismiss();
    }
    private void removePrivateDownload(ForegroundDownload.Result result) {
        try{Files.deleteIfExists(result.path);}catch(IOException ignored){if(result==downloaded&&session.ownsView(downloadOwner))state.setText(R.string.download_cleanup_pending);}
    }
    private void discardDownload(boolean announce) {
        cancelDownloadPrompt();downloadIdentity=null;downloadOwner=null;
        if(downloading!=null)downloading.cancel();downloading=null;
        if(exporting!=null)exporting.cancel();exporting=null;
        if(downloadSelection!=null){session.cancelSelection();downloadSelection=null;}
        if(exportLauncher!=null)exportLauncher.unregister();exportLauncher=null;
        if(downloaded!=null)removePrivateDownload(downloaded);downloaded=null;
        downloadControls.setVisibility(View.GONE);saveDownload.setEnabled(false);if(announce)state.setText(R.string.download_cancelled);
    }
    private void chooseDownloadDestination() {
        if(downloaded==null||downloading!=null||exporting!=null||downloadSelection!=null||!session.interactive()||!session.ownsView(downloadOwner))return;
        SessionCallbacks.Ticket ticket=session.beginSelection();if(ticket==null)return;downloadSelection=ticket;
        UUID identity=downloadIdentity;SessionCallbacks.Ticket owner=downloadOwner;
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.setType(downloaded.mime);intent.addCategory(Intent.CATEGORY_OPENABLE);intent.putExtra(Intent.EXTRA_TITLE,downloaded.filename);
        try{
            exportLauncher=getActivityResultRegistry().register("save-"+UUID.randomUUID(),new ActivityResultContracts.StartActivityForResult(),result->{
                if(downloadSelection!=ticket||identity==null||!identity.equals(downloadIdentity)||!session.ownsView(owner)||!session.awaitingSelection(ticket.requestCode))return;
                ActivityResultLauncher<Intent> completed=exportLauncher;exportLauncher=null;if(completed!=null)completed.unregister();
                Intent data=result.getData();Uri selected=result.getResultCode()==RESULT_OK&&data!=null?data.getData():null;
                if(selected!=null&&!"content".equals(selected.getScheme()))selected=null;
                if(session.receiveSelection(ticket.requestCode,selected==null?null:new Uri[]{selected}))deliverDownloadDestination();
            });exportLauncher.launch(intent);
        }catch(RuntimeException failure){if(exportLauncher!=null)exportLauncher.unregister();exportLauncher=null;session.cancelSelection();downloadSelection=null;tell(R.string.file_picker_unavailable);}
    }
    private void deliverDownloadDestination() {
        if(downloadSelection==null||downloaded==null||exporting!=null||!session.interactive()||!session.ownsView(downloadOwner))return;
        SessionCallbacks.Selection<Uri[]> chosen=session.takeSelection();if(chosen==null)return;downloadSelection=null;
        if(chosen.value==null||chosen.value.length!=1){downloadState.setText(R.string.download_save_cancelled);return;}
        final UUID identity=downloadIdentity;final ForegroundDownload.Result original=downloaded;saveDownload.setEnabled(false);downloadState.setText(R.string.download_saving);
        NativeFileExport operation=new NativeFileExport(getContentResolver(),original,chosen.value[0],getMainExecutor(),outcome->{
            if(identity==null||!identity.equals(downloadIdentity)||downloaded!=original)return;
            exporting=null;saveDownload.setEnabled(true);
            if(outcome==NativeFileExport.Outcome.VERIFIED){removePrivateDownload(original);downloaded=null;downloadIdentity=null;downloadOwner=null;downloadControls.setVisibility(View.GONE);state.setText(R.string.download_saved);}
            else{downloadState.setText(outcome==NativeFileExport.Outcome.UNVERIFIED?R.string.download_save_unverified:outcome==NativeFileExport.Outcome.BUSY?R.string.download_busy:R.string.download_save_failed);}
        });exporting=operation;operation.start();
    }
    private static Uri[] selectedUris(int result, Intent data) {
        java.util.LinkedHashSet<Uri> selected = new java.util.LinkedHashSet<>();
        if (result == RESULT_OK && data != null) {
            if (data.getData() != null && "content".equals(data.getData().getScheme())) selected.add(data.getData());
            if (data.getClipData() != null) for (int i = 0; i < Math.min(32, data.getClipData().getItemCount()) && selected.size() < 32; i++) {
                Uri uri = data.getClipData().getItemAt(i).getUri(); if ("content".equals(uri.getScheme())) selected.add(uri);
            }
        }
        return selected.isEmpty()?null:selected.toArray(new Uri[0]);
    }
    private void cancelFiles() {
        if(uploadLauncher!=null)uploadLauncher.unregister();uploadLauncher=null;uploadSelection=null;
        session.cancelSelection(); ValueCallback<Uri[]> callback = files; files = null;
        if (callback != null) callback.onReceiveValue(null);
    }
    private void deliverFiles() {
        if(files==null)return;
        SessionCallbacks.Selection<Uri[]> selected = session.takeSelection();
        if (selected == null || files == null) return;
        ValueCallback<Uri[]> callback = files; files = null;
        uploadSelection=null;
        if (web == null || address == null || !address.allows(web.getUrl())) callback.onReceiveValue(null);
        else callback.onReceiveValue(selected.value);
    }
    @Override protected void onResume() { super.onResume(); session.foreground(true); }
    @Override protected void onPause() {
        super.onPause();
        session.foreground(false);
        downloadControls.setVisibility(View.GONE);
        cancelDownloadPrompt();
        if(downloading!=null){discardDownload(false);state.setText(R.string.download_cancelled);}
        if(exporting!=null)exporting.cancel();
        cancelPageDialog();
        if (authentication != null) authentication.cancel(); authentication = null;
        coverWeb();
    }
    private void coverWeb() {
        if (web == null) return;
        // An opaque overlay alone still exposes the page to accessibility.
        // Hide the actual view and its descendants before displaying the lock.
        web.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        web.setVisibility(View.INVISIBLE);
        web.onPause(); web.pauseTimers();
        if (lock.getParent() == null) frame.addView(lock, new FrameLayout.LayoutParams(-1, -1));
        controls.setVisibility(View.GONE);
    }
    private void restoreAuthenticatedWeb() {
        if (web == null || closed || isFinishing() || !session.interactive()) return;
        web.setVisibility(View.VISIBLE);
        web.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_AUTO);
        frame.removeView(lock); controls.setVisibility(View.VISIBLE);
        web.onResume(); web.resumeTimers(); deliverFiles();deliverDownloadDestination();
        if(downloaded!=null||downloading!=null||exporting!=null)downloadControls.setVisibility(View.VISIBLE);
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
                restoreAuthenticatedWeb();
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
        if (webRuntimeUnavailable) return;
        if (!resetting.compareAndSet(false, true)) return;
        clearing = true;
        try {
            WebStorage.getInstance().deleteAllData();
            CookieManager.getInstance().removeAllCookies(success -> {
                try { CookieManager.getInstance().flush(); }
                catch (RuntimeException unavailable) { unavailableWebRuntime(); return; }
                clearing = false; resetting.set(false); if (done != null) done.run();
            });
        } catch (RuntimeException unavailable) { unavailableWebRuntime(); }
    }
    private void unavailableWebRuntime() {
        webRuntimeUnavailable = true; clearing = false; resetting.set(false);
        state.setText(R.string.webview_update_required);
    }
    private void destroyWeb() {
        discardDownload(false);
        session.end();
        cancelPageDialog();
        if (authentication != null) authentication.cancel(); authentication = null;
        cancelFiles();
        if (web != null) { web.stopLoading(); web.resumeTimers(); web.clearCache(true); web.clearHistory(); frame.removeAllViews(); web.destroy(); web = null; }
        progress.setVisibility(View.GONE);
    }
    @Override protected void onDestroy() { closed = true; if (authentication != null) authentication.cancel(); destroyWeb(); clearLocal(null); super.onDestroy(); }
}
