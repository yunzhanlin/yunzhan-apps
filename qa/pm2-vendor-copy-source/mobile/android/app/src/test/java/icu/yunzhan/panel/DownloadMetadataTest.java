package icu.yunzhan.panel;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class DownloadMetadataTest {
    private DownloadMetadata parse(String value){return new DownloadMetadata(value,"application/octet-stream",null,null,null);}
    @Test public void quotedSemicolonAndExtendedUtf8RemainDisplayNames(){
        assertEquals("a;b.txt",parse("attachment; filename=\"a;b.txt\"").filename);
        assertEquals("备份+.txt",parse("attachment; filename=fallback.txt; filename*=UTF-8''%E5%A4%87%E4%BB%BD+.txt").filename);
    }
    @Test public void pathsControlsAndBidiCannotBecomeStoragePaths(){
        String value=parse("attachment; filename=\"../../private/秘密.txt\"").filename;
        assertFalse(value.contains("/"));assertFalse(value.contains("\\"));assertFalse(value.equals(".."));
        assertEquals(".env",DownloadMetadata.safeName(".env"));
        assertEquals("a_b.txt",DownloadMetadata.safeName("a\u202eb.txt"));assertEquals("yunzhan-download.bin",DownloadMetadata.safeName(".."));
    }
    @Test public void unicodeNameLimitPreservesUtf8Boundaries(){
        String name=new String(new char[300]).replace("\0","界");String safe=DownloadMetadata.safeName(name);
        assertTrue(safe.getBytes(StandardCharsets.UTF_8).length<=180);assertFalse(safe.contains("\ufffd"));assertFalse(safe.isEmpty());
    }
    @Test public void malformedMetadataFailsRatherThanGuessing(){
        for(String value:new String[]{"inline; filename=x","attachment; filename=\"unfinished","attachment; filename=a; filename=b","attachment; filename*=UTF-8''%FF.txt","attachment; filename=x\r\nInjected: x"}){
            try{parse(value);fail(value);}catch(IllegalArgumentException expected){assertNotNull(expected);}
        }
        for(String length:new String[]{"-1","1,2","9223372036854775808","x"}){
            try{new DownloadMetadata("attachment",null,length,null,null);fail(length);}catch(IllegalArgumentException expected){assertNotNull(expected);}
        }
        try{new DownloadMetadata("attachment",null,null,"gzip",null);fail("encoded file");}catch(IllegalArgumentException expected){assertNotNull(expected);}
    }
}
