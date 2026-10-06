package icu.yunzhan.panel;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/** One exact scheme/host/effective-port origin, never suffix matching. */
public final class PanelAddress {
    public final URI uri;
    private PanelAddress(URI uri) { this.uri = uri; }
    public static PanelAddress parse(String raw, boolean debug) {
        try {
            URI uri = strict(raw);
            if (uri.getRawQuery() != null || uri.getRawFragment() != null || !uri.normalize().equals(uri) || java.util.Arrays.stream(uri.getPath().split("/")).anyMatch(s -> s.equals(".") || s.equals(".."))) throw new IllegalArgumentException();
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost().toLowerCase(Locale.ROOT);
            boolean loopback = host.equals("127.0.0.1") || host.equals("10.0.2.2") || host.equals("localhost") || host.equals("[::1]");
            if (!scheme.equals("https") && !(debug && scheme.equals("http") && loopback)) throw new IllegalArgumentException();
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) uri = URI.create(uri.toString() + "/");
            return new PanelAddress(uri);
        } catch (RuntimeException | URISyntaxException e) {
            throw new IllegalArgumentException("请输入完整 HTTPS 面板地址，不含账号、临时令牌、查询参数或片段。QA 仅允许回环 HTTP。");
        }
    }
    private static URI strict(String raw) throws URISyntaxException {
        if (raw == null || raw.length() > 2048 || raw.indexOf('\\') >= 0 || raw.chars().anyMatch(c -> c <= 32 || c >= 127)) throw new IllegalArgumentException();
        URI uri = new URI(raw);
        if (uri.isOpaque() || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawAuthority().contains("%") || uri.getPort() == 0 || uri.getPort() > 65535 || uri.getPort() < -1) throw new IllegalArgumentException();
        if (uri.getScheme() == null) throw new IllegalArgumentException();
        return uri;
    }
    private static int port(URI uri) { return uri.getPort() < 0 ? (uri.getScheme().equalsIgnoreCase("https") ? 443 : 80) : uri.getPort(); }
    public boolean allows(String raw) {
        try {
            URI target = strict(raw);
            return uri.getScheme().equalsIgnoreCase(target.getScheme()) && uri.getHost().equalsIgnoreCase(target.getHost()) && port(uri) == port(target);
        } catch (RuntimeException | URISyntaxException e) { return false; }
    }
    public String displayOrigin() { return uri.getScheme() + "://" + uri.getRawAuthority(); }
}
