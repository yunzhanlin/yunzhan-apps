package icu.yunzhan.panel;

import org.junit.Test;
import static org.junit.Assert.*;

public class PanelAddressTest {
    @Test public void actualAPI30OriginalEngineIsRefused() {
        assertFalse(PanelActivity.supportsWebViewVersion("83.0.4103.120"));
        assertFalse(PanelActivity.supportsWebViewVersion("110.0.5481.77"));
    }
    @Test public void browserEngineBoundaryIsIndependentOfAndroidAPI() {
        assertTrue(PanelActivity.supportsWebViewVersion("111.0.5563.58"));
        assertTrue(PanelActivity.supportsWebViewVersion("128.0.6613.88"));
        assertTrue(PanelActivity.supportsWebViewVersion("153.0.8000.1"));
        assertFalse(PanelActivity.supportsWebViewVersion("37.0.0.0"));
    }
    @Test public void missingOrMalformedProviderVersionDoesNotConnect() {
        for (String version : new String[]{null,"","111","111.0","111.0.0.0-preview","111.0.0.0 "," 111.0.0.0","0111.0.0.0","999999999999999.0.0.0","111.0.0.0.0"}) {
            assertFalse(String.valueOf(version),PanelActivity.supportsWebViewVersion(version));
        }
    }
    @Test public void versionLabelsCannotMasqueradeAsProviderVersion() {
        for (String version : new String[]{"Android 17 Chrome/153.0.0.0","Chromium 153.0.0.0","1.153.0.0","83.0.0.0/153.0.0.0"}) {
            assertFalse(version,PanelActivity.supportsWebViewVersion(version));
        }
    }
    @Test public void strictOriginAndEntry() {
        PanelAddress p = PanelAddress.parse("https://panel.example:2443/private-entry/", false);
        assertTrue(p.allows("https://panel.example:2443/api/me?test=1"));
        assertTrue(p.allows("https://PANEL.example:2443/#files"));
        for (String u : new String[]{"https://panel.example.evil:2443/", "http://panel.example:2443/", "https://panel.example/", "https://panel.example:2444/", "https://evil@panel.example:2443/", "javascript://panel.example:2443/", "file:///tmp/foo", "content://panel.example:2443/a", "https://panel.example:2443\\@evil/", "https://%70anel.example:2443/", "//panel.example:2443/a"}) assertFalse(u, p.allows(u));
        assertTrue(PanelAddress.parse("https://panel.example/", false).allows("https://panel.example:443/api/me"));
    }
    @Test public void rejectsCredentialsTokensAndMalformedInputs() {
        for (String u : new String[]{"http://panel.example/", "https://u:p@panel.example/", "https://panel.example/?tmp_token=secret", "https://panel.example/#password", "https://panel.example/../secret", "https://panel.example:0/", "https://panel.example:99999/", "https://panel.example\n/", "https://面板.example/", "https://panel.example\\/"}) {
            try { PanelAddress.parse(u, false); fail(u); } catch (IllegalArgumentException expected) { }
        }
    }
    @Test public void loopbackHTTPIsDebugOnly() {
        assertTrue(PanelAddress.parse("http://10.0.2.2:19220/", true).allows("http://10.0.2.2:19220/api/me"));
        for (String u : new String[]{"http://10.0.2.2:19220/", "http://127.0.0.1:19100/"}) {
            try { PanelAddress.parse(u, false); fail(u); } catch (IllegalArgumentException expected) { }
        }
        try { PanelAddress.parse("http://192.168.1.1/", true); fail(); } catch (IllegalArgumentException expected) { }
    }
}
