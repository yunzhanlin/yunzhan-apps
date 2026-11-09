package icu.yunzhan.panel;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Untrusted response metadata supplies a display name, never a storage path. */
final class DownloadMetadata {
    final String filename, mime, sha256;
    final long length;
    DownloadMetadata(String disposition, String type, String length, String encoding, String checksum) {
        if (disposition == null || disposition.length() > 8192 || disposition.indexOf('\r') >= 0 || disposition.indexOf('\n') >= 0)
            throw new IllegalArgumentException("attachment required");
        List<String> fields = fields(disposition);
        if (fields.isEmpty() || !fields.get(0).trim().equalsIgnoreCase("attachment"))
            throw new IllegalArgumentException("attachment required");
        if (encoding != null && !encoding.trim().isEmpty() && !encoding.trim().equalsIgnoreCase("identity"))
            throw new IllegalArgumentException("encoded attachment refused");
        String ordinary = null, extended = null;
        for (int i = 1; i < fields.size(); i++) {
            String field = fields.get(i); int split = field.indexOf('=');
            if (split < 1) continue;
            String key = field.substring(0, split).trim().toLowerCase(Locale.ROOT);
            String value = field.substring(split + 1).trim();
            if (key.equals("filename")) {
                if (ordinary != null) throw new IllegalArgumentException("duplicate filename");
                ordinary = unquote(value);
            } else if (key.equals("filename*")) {
                if (extended != null) throw new IllegalArgumentException("duplicate filename");
                extended = extended(value);
            }
        }
        filename = safeName(extended != null ? extended : ordinary);
        String candidate = type == null ? "" : type.split(";", 2)[0].trim();
        mime = candidate.length() <= 128 && candidate.matches("[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+")
            ? candidate.toLowerCase(Locale.ROOT) : "application/octet-stream";
        if (length == null) this.length = -1;
        else {
            if (!length.matches("[0-9]{1,19}")) throw new IllegalArgumentException("invalid attachment length");
            try { this.length = Long.parseLong(length); }
            catch (NumberFormatException e) { throw new IllegalArgumentException("invalid attachment length"); }
        }
        sha256 = checksum == null ? "" : checksum.trim().toLowerCase(Locale.ROOT);
        if (!sha256.isEmpty() && !sha256.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid attachment digest");
    }
    private static List<String> fields(String source) {
        List<String> values = new ArrayList<>(); StringBuilder current = new StringBuilder();
        boolean quoted = false, escape = false;
        for (int i = 0; i < source.length(); i++) {
            char ch = source.charAt(i);
            if (escape) { current.append(ch); escape = false; continue; }
            if (quoted && ch == '\\') { current.append(ch); escape = true; continue; }
            if (ch == '"') quoted = !quoted;
            if (ch == ';' && !quoted) { values.add(current.toString()); current.setLength(0); }
            else current.append(ch);
        }
        if (quoted || escape) throw new IllegalArgumentException("invalid attachment name");
        values.add(current.toString()); return values;
    }
    private static String unquote(String source) {
        if (!source.startsWith("\"")) return source;
        if (source.length() < 2 || !source.endsWith("\"")) throw new IllegalArgumentException("invalid attachment name");
        StringBuilder value = new StringBuilder();
        for (int i = 1; i < source.length() - 1; i++) {
            char ch = source.charAt(i);
            if (ch == '\\') { if (++i >= source.length() - 1) throw new IllegalArgumentException("invalid attachment name"); ch = source.charAt(i); }
            value.append(ch);
        }
        return value.toString();
    }
    private static String extended(String source) {
        int first = source.indexOf('\''), second = source.indexOf('\'', first + 1);
        if (first < 0 || second < 0 || !source.substring(0, first).equalsIgnoreCase("UTF-8"))
            throw new IllegalArgumentException("invalid UTF-8 attachment name");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (int i = second + 1; i < source.length(); i++) {
            char ch = source.charAt(i);
            if (ch == '%') {
                if (i + 2 >= source.length()) throw new IllegalArgumentException("invalid UTF-8 attachment name");
                int hi = Character.digit(source.charAt(++i), 16), lo = Character.digit(source.charAt(++i), 16);
                if (hi < 0 || lo < 0) throw new IllegalArgumentException("invalid UTF-8 attachment name");
                bytes.write((hi << 4) | lo);
            } else { if (ch > 127 || ch < 33) throw new IllegalArgumentException("invalid UTF-8 attachment name"); bytes.write(ch); }
        }
        try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString(); }
        catch (CharacterCodingException e) { throw new IllegalArgumentException("invalid UTF-8 attachment name"); }
    }
    static String safeName(String source) {
        if (source == null) return "yunzhan-download.bin";
        StringBuilder result = new StringBuilder(); int bytes = 0;
        for (int offset = 0; offset < source.length();) {
            int cp = source.codePointAt(offset); offset += Character.charCount(cp);
            if (cp == '/' || cp == '\\' || Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT || Character.getType(cp) == Character.SURROGATE)
                cp = '_';
            String part = new String(Character.toChars(cp)); int count = part.getBytes(StandardCharsets.UTF_8).length;
            if (bytes + count > 180) break;
            result.append(part); bytes += count;
        }
        String value = result.toString().trim();
        return value.isEmpty() || value.equals(".") || value.equals("..") ? "yunzhan-download.bin" : value;
    }
}
