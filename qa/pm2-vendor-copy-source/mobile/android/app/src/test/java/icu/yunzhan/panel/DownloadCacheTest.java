package icu.yunzhan.panel;

import static org.junit.Assert.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.UUID;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class DownloadCacheTest {
    private Path appCache,root,original;
    @Before public void setup()throws Exception{
        appCache=Files.createTempDirectory("owned-download-cache-test-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        root=Files.createDirectory(appCache.resolve("native-downloads"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        original=appCache.resolve("selected-user-document.txt");Files.write(original,new byte[]{1,2,3});Files.setPosixFilePermissions(original,PosixFilePermissions.fromString("rw-------"));
    }
    @After public void cleanup()throws Exception{
        try(java.util.stream.Stream<Path> files=Files.walk(appCache)){for(Path p:(Iterable<Path>)files.sorted(Comparator.reverseOrder())::iterator)Files.delete(p);}
    }
    private Path name(){return root.resolve("download-"+UUID.randomUUID()+".part");}
    private void refused()throws Exception{try{DownloadCache.prepare(appCache);fail("unknown cache state was repaired");}catch(IOException expected){assertNotNull(expected);}}
    @Test public void processRestartRemovesOnlyKnownUnexportedTemporaryFiles()throws Exception{
        Path partial=name();Files.write(partial,new byte[]{5,6});Files.setPosixFilePermissions(partial,PosixFilePermissions.fromString("rw-------"));Object rootID=Files.getAttribute(root,"unix:ino",LinkOption.NOFOLLOW_LINKS);
        assertEquals(root,DownloadCache.prepare(appCache));assertFalse(Files.exists(partial,LinkOption.NOFOLLOW_LINKS));assertArrayEquals(new byte[]{1,2,3},Files.readAllBytes(original));assertEquals(rootID,Files.getAttribute(root,"unix:ino",LinkOption.NOFOLLOW_LINKS));
    }
    @Test public void anotherActivityNeverPurgesAnAlreadyReceivedFileInThisProcess()throws Exception{
        assertEquals(root,DownloadCache.prepare(appCache));Path ready=name();Files.write(ready,new byte[]{5,6});Files.setPosixFilePermissions(ready,PosixFilePermissions.fromString("rw-------"));
        assertEquals(root,DownloadCache.prepare(appCache));assertArrayEquals(new byte[]{5,6},Files.readAllBytes(ready));
    }
    @Test public void symbolicLinksAndTheirTargetsArePreservedOnRefusal()throws Exception{
        Path link=name();Files.createSymbolicLink(link,original);Object identity=Files.getAttribute(link,"unix:ino",LinkOption.NOFOLLOW_LINKS);refused();assertTrue(Files.isSymbolicLink(link));assertEquals(identity,Files.getAttribute(link,"unix:ino",LinkOption.NOFOLLOW_LINKS));assertArrayEquals(new byte[]{1,2,3},Files.readAllBytes(original));
    }
    @Test public void hardLinkedOriginalDocumentIsNeverDeletedOrRepaired()throws Exception{
        Path link=name();Files.createLink(link,original);Object identity=Files.getAttribute(original,"unix:ino",LinkOption.NOFOLLOW_LINKS);refused();assertEquals(identity,Files.getAttribute(link,"unix:ino",LinkOption.NOFOLLOW_LINKS));assertEquals(2,((Number)Files.getAttribute(original,"unix:nlink",LinkOption.NOFOLLOW_LINKS)).intValue());assertArrayEquals(new byte[]{1,2,3},Files.readAllBytes(original));
    }
    @Test public void writableDirectoryAndUnknownEntriesAreRetained()throws Exception{
        Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwxrwx---"));refused();assertEquals(PosixFilePermissions.fromString("rwxrwx---"),Files.getPosixFilePermissions(root));
        Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"));Path unknown=root.resolve("unknown-evidence.json");Files.write(unknown,new byte[]{7});refused();assertArrayEquals(new byte[]{7},Files.readAllBytes(unknown));
    }
}
