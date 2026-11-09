package icu.yunzhan.panel;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashSet;
import java.util.Set;

/** Remove only this app's unexported temporary files after a process restart. */
final class DownloadCache {
    private static final Set<Path> PREPARED = new HashSet<>();
    private DownloadCache() { }
    static synchronized Path prepare(Path appCache) throws IOException {
        Path root=appCache.resolve("native-downloads");
        if(!Files.exists(root,LinkOption.NOFOLLOW_LINKS))Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(root)||!Files.getOwner(root,LinkOption.NOFOLLOW_LINKS).equals(Files.getOwner(appCache,LinkOption.NOFOLLOW_LINKS))||!Files.getPosixFilePermissions(root,LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString("rwx------")))throw new IOException("private cache refused");
        if(PREPARED.contains(root))return root;
        if(!NativeTransferBudget.acquire())throw new IOException("original transfer remains active");
        try(DirectoryStream<Path> entries=Files.newDirectoryStream(root)){
            int count=0;
            for(Path file:entries){
                if(++count>128||!file.getFileName().toString().matches("download-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.part")||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(file)||((Number)Files.getAttribute(file,"unix:nlink",LinkOption.NOFOLLOW_LINKS)).longValue()!=1||!Files.getOwner(file,LinkOption.NOFOLLOW_LINKS).equals(Files.getOwner(root,LinkOption.NOFOLLOW_LINKS))||!Files.getPosixFilePermissions(file,LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString("rw-------")))throw new IOException("unrecognized temporary file retained");
                Files.delete(file);
            }
        } finally { NativeTransferBudget.release(); }
        PREPARED.add(root);return root;
    }
}
