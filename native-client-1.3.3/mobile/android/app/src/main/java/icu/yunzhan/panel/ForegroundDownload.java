package icu.yunzhan.panel;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/** A single anonymous-to-the-OS, same-origin transfer. No redirects or retries. */
final class ForegroundDownload {
    static final long MAX_BYTES = 2L * 1024 * 1024 * 1024;
    static final long RESERVE_BYTES = 128L * 1024 * 1024;
    enum Failure { CANCELLED, NETWORK, RESPONSE, CAPACITY, INTEGRITY, STORAGE, BUSY }
    interface Listener {
        void progress(long received, long expected);
        void complete(Result file);
        void failed(Failure reason);
    }
    static final class Result {
        final Path path;
        final String filename, mime, sha256;
        final long bytes;
        final boolean serverDigestVerified;
        Result(Path path, DownloadMetadata metadata, String sha256, long bytes) {
            this.path = path; filename = metadata.filename; mime = metadata.mime;
            this.sha256 = sha256; this.bytes = bytes; serverDigestVerified = !metadata.sha256.isEmpty();
        }
    }
    private final PanelAddress address;
    private final String url, userAgent;
    private String cookie;
    private final Path directory;
    private final Executor callbacks;
    private final Listener listener;
    private final long maximum, reserve;
    private final AtomicBoolean started = new AtomicBoolean(), cancelled = new AtomicBoolean();
    private volatile HttpURLConnection connection;
    private volatile InputStream input;

    ForegroundDownload(PanelAddress address, String url, String cookie, String userAgent, Path directory, Executor callbacks, Listener listener) {
        this(address, url, cookie, userAgent, directory, callbacks, listener, MAX_BYTES, RESERVE_BYTES);
    }
    ForegroundDownload(PanelAddress address, String url, String cookie, String userAgent, Path directory, Executor callbacks, Listener listener, long maximum, long reserve) {
        if (address == null || !address.allows(url) || maximum < 1 || maximum > MAX_BYTES || reserve < 0)
            throw new IllegalArgumentException("download origin or limits refused");
        this.address = address; this.url = url; this.cookie = cookie == null ? "" : cookie;
        this.userAgent = userAgent == null ? "YunzhanMobile" : userAgent;
        if (this.cookie.length() > 32768 || containsControls(this.cookie) || containsControls(this.userAgent))
            throw new IllegalArgumentException("download headers refused");
        this.directory = directory; this.callbacks = callbacks; this.listener = listener; this.maximum = maximum; this.reserve = reserve;
    }
    private static boolean containsControls(String value) {
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) < 32 || value.charAt(i) == 127) return true;
        return false;
    }
    void start() {
        if (!started.compareAndSet(false, true)) throw new IllegalStateException("original transfer already submitted");
        if (!NativeTransferBudget.acquire()) { cookie=""; callbacks.execute(()->listener.failed(Failure.BUSY)); return; }
        try { Thread worker = new Thread(this::receive, "panel-foreground-download"); worker.setDaemon(true); worker.start(); }
        catch(RuntimeException | Error failure){NativeTransferBudget.release();throw failure;}
    }
    void cancel() {
        if (!cancelled.compareAndSet(false, true)) return;
        // Closing a network stream can block. Never make privacy locking wait
        // on an unresponsive peer or file provider on the Activity thread.
        Thread closer = new Thread(() -> {
            HttpURLConnection current = connection; if (current != null) current.disconnect();
            InputStream stream = input; if (stream != null) try { stream.close(); } catch (IOException ignored) { }
        }, "panel-download-cancel"); closer.setDaemon(true); closer.start();
    }
    boolean cancelled() { return cancelled.get(); }
    private void requireActive(long deadline) throws Refused {
        if (cancelled.get()) throw new Refused(Failure.CANCELLED);
        if (System.nanoTime() > deadline) throw new Refused(Failure.NETWORK);
    }
    private static String header(HttpURLConnection connection, String name) throws Refused {
        String value = null;
        for (Map.Entry<String,List<String>> row : connection.getHeaderFields().entrySet()) {
            if (row.getKey() == null || !row.getKey().equalsIgnoreCase(name)) continue;
            if (value != null || row.getValue().size() != 1) throw new Refused(Failure.RESPONSE);
            value = row.getValue().get(0);
        }
        return value;
    }
    private void receive() {
        Path partial = null; Result completed = null; Failure failure = Failure.NETWORK;
        long deadline = System.nanoTime() + 5L * 60 * 1_000_000_000;
        try {
            requireActive(deadline);
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(directory)) throw new Refused(Failure.STORAGE);
            Set<java.nio.file.attribute.PosixFilePermission> permissions = Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS);
            if (!permissions.equals(PosixFilePermissions.fromString("rwx------"))) throw new Refused(Failure.STORAGE);
            if (Files.getFileStore(directory).getUsableSpace() <= reserve) throw new Refused(Failure.CAPACITY);
            URL target = new URL(url); if (!address.allows(target.toString())) throw new Refused(Failure.RESPONSE);
            HttpURLConnection c = (HttpURLConnection)target.openConnection(); connection = c;
            c.setInstanceFollowRedirects(false); c.setConnectTimeout(15000); c.setReadTimeout(15000);
            c.setUseCaches(false); c.setRequestMethod("GET"); c.setRequestProperty("Accept-Encoding", "identity");
            c.setRequestProperty("Cache-Control", "no-store"); c.setRequestProperty("User-Agent", userAgent);
            if (!cookie.isEmpty()) c.setRequestProperty("Cookie", cookie);
            requireActive(deadline);
            if (c.getResponseCode() != 200) throw new Refused(Failure.RESPONSE);
            DownloadMetadata metadata;
            try { metadata = new DownloadMetadata(header(c,"Content-Disposition"), header(c,"Content-Type"), header(c,"Content-Length"), header(c,"Content-Encoding"), header(c,"X-Content-SHA256")); }
            catch (IllegalArgumentException e) { throw new Refused(Failure.RESPONSE); }
            if (metadata.length > maximum || metadata.length > Files.getFileStore(directory).getUsableSpace() - reserve) throw new Refused(Failure.CAPACITY);
            if (header(c,"Transfer-Encoding") != null && metadata.length >= 0) throw new Refused(Failure.RESPONSE);
            requireActive(deadline);
            partial = directory.resolve("download-" + UUID.randomUUID() + ".part");
            MessageDigest digest = MessageDigest.getInstance("SHA-256"); long received = 0, lastProgress = 0;
            try (FileChannel file = FileChannel.open(partial, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                 InputStream stream = c.getInputStream()) {
                input = stream; byte[] buffer = new byte[65536]; int count;
                while ((count = stream.read(buffer)) != -1) {
                    requireActive(deadline);
                    if (count > maximum - received) throw new Refused(Failure.CAPACITY);
                    if (metadata.length >= 0 && count > metadata.length - received) throw new Refused(Failure.INTEGRITY);
                    if (count > Files.getFileStore(directory).getUsableSpace() - reserve) throw new Refused(Failure.CAPACITY);
                    digest.update(buffer,0,count); ByteBuffer bytes = ByteBuffer.wrap(buffer,0,count);
                    while (bytes.hasRemaining()) file.write(bytes);
                    received += count;
                    long now = System.nanoTime();
                    if (now - lastProgress >= 100_000_000) { long current = received; callbacks.execute(() -> listener.progress(current, metadata.length)); lastProgress = now; }
                }
                requireActive(deadline);
                if (metadata.length >= 0 && received != metadata.length) throw new Refused(Failure.INTEGRITY);
                String actual = hex(digest.digest());
                if (!metadata.sha256.isEmpty() && !MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII), metadata.sha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) throw new Refused(Failure.INTEGRITY);
                file.force(true); completed = new Result(partial,metadata,actual,received);
            } finally { input = null; }
        } catch (Refused e) { failure = e.reason; }
        catch (IOException e) { failure = cancelled.get() ? Failure.CANCELLED : Failure.NETWORK; }
        catch (NoSuchAlgorithmException | RuntimeException e) { failure = Failure.STORAGE; }
        finally { cookie = ""; HttpURLConnection current = connection; connection = null; try { if (current != null) current.disconnect(); } finally { NativeTransferBudget.release(); } }
        if (cancelled.get()) { completed = null; failure = Failure.CANCELLED; }
        if (completed == null) {
            if (partial != null) try { Files.deleteIfExists(partial); } catch (IOException ignored) { }
            Failure result = failure; callbacks.execute(() -> listener.failed(result));
        } else { Result result = completed; callbacks.execute(() -> listener.complete(result)); }
    }
    static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) { value.append(Character.forDigit((item & 255) >>> 4,16)); value.append(Character.forDigit(item & 15,16)); }
        return value.toString();
    }
    private static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;
        final Failure reason; Refused(Failure reason) { this.reason = reason; }
    }
}
