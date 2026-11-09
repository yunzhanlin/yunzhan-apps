package icu.yunzhan.panel;

import static org.junit.Assert.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/** Real bounded HTTP streams, failures and cancellation; no Android mocks. */
public final class ForegroundDownloadTest {
    private Path directory;
    private OwnedDownloadServer server;
    private ExecutorService executor;
    private PanelAddress address;
    private String origin;
    private final byte[] payload = new byte[131137];
    @Before public void setup() throws Exception {
        for (int i=0;i<payload.length;i++) payload[i]=(byte)(i*31);
        directory=Files.createTempDirectory("panel-download-test-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        server=OwnedDownloadServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        executor=Executors.newCachedThreadPool(r->{Thread t=new Thread(r,"owned-download-test-server");t.setDaemon(true);return t;});server.setExecutor(executor);
        server.start();origin="http://127.0.0.1:"+server.getAddress().getPort();address=PanelAddress.parse(origin,true);
    }
    @After public void cleanup() throws Exception {
        server.stop(0);executor.shutdownNow();assertTrue(executor.awaitTermination(5,TimeUnit.SECONDS));
        try(java.util.stream.Stream<Path> entries=Files.walk(directory)){
            for(Path p:(Iterable<Path>)entries.sorted(Comparator.reverseOrder())::iterator)Files.delete(p);
        }
    }
    private static final class Capture implements ForegroundDownload.Listener {
        final CountDownLatch terminal=new CountDownLatch(1);
        final AtomicReference<ForegroundDownload.Result> result=new AtomicReference<>();
        final AtomicReference<ForegroundDownload.Failure> failure=new AtomicReference<>();
        final AtomicInteger completions=new AtomicInteger();
        public void progress(long received,long expected){assertTrue(received>=0);assertTrue(expected<0||received<=expected);}
        public void complete(ForegroundDownload.Result file){result.set(file);completions.incrementAndGet();terminal.countDown();}
        public void failed(ForegroundDownload.Failure reason){failure.set(reason);completions.incrementAndGet();terminal.countDown();}
        void await()throws Exception{assertTrue("original transfer must settle",terminal.await(10,TimeUnit.SECONDS));assertEquals(1,completions.get());}
    }
    private ForegroundDownload task(String path,Capture captured,long maximum){
        return new ForegroundDownload(address,origin+path,"panel_session=owned-fixture","OwnedTest/1",directory,Runnable::run,captured,maximum,0);
    }
    private void noPartial()throws Exception{try(java.util.stream.Stream<Path> files=Files.list(directory)){assertEquals(0,files.count());}}
    private void attachment(String path,byte[] bytes,String digest,boolean chunked){
        server.createContext(path,e->{
            if(!"panel_session=owned-fixture".equals(e.getRequestHeaders().getFirst("Cookie"))||!"identity".equals(e.getRequestHeaders().getFirst("Accept-Encoding"))){e.sendResponseHeaders(401,-1);e.close();return;}
            e.getResponseHeaders().add("Content-Disposition","attachment; filename*=UTF-8''%E5%A4%87%E4%BB%BD%2B.bin");
            e.getResponseHeaders().add("Content-Type","application/octet-stream");
            if(digest!=null)e.getResponseHeaders().add("X-Content-SHA256",digest);
            e.sendResponseHeaders(200,chunked?0:bytes.length);
            try{e.getResponseBody().write(bytes);}finally{e.close();}
        });
    }
    @Test public void exactBytesDigestPrivateModeAndOriginalName()throws Exception{
        String digest=ForegroundDownload.hex(MessageDigest.getInstance("SHA-256").digest(payload));attachment("/download",payload,digest,false);
        Capture c=new Capture();ForegroundDownload t=task("/download",c,1<<20);t.start();c.await();assertNull(c.failure.get());
        ForegroundDownload.Result r=c.result.get();assertNotNull(r);assertEquals("备份+.bin",r.filename);assertEquals(payload.length,r.bytes);assertEquals(digest,r.sha256);assertTrue(r.serverDigestVerified);
        assertArrayEquals(payload,Files.readAllBytes(r.path));assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(r.path));
        assertEquals(directory,r.path.getParent());assertFalse(Files.isSymbolicLink(r.path));
        try{t.start();fail("same original transfer submitted twice");}catch(IllegalStateException expected){assertNotNull(expected);}
    }
    @Test public void chunkedBodyStillHasAnActualDigest()throws Exception{
        attachment("/chunked",payload,null,true);Capture c=new Capture();task("/chunked",c,1<<20).start();c.await();assertNull(c.failure.get());
        assertEquals(payload.length,c.result.get().bytes);assertFalse(c.result.get().serverDigestVerified);assertArrayEquals(payload,Files.readAllBytes(c.result.get().path));
    }
    @Test public void wrongServerDigestDoesNotLeaveAnExportableFile()throws Exception{
        attachment("/wrong",payload,new String(new char[64]).replace('\0','0'),false);Capture c=new Capture();task("/wrong",c,1<<20).start();c.await();assertNull(c.result.get());assertEquals(ForegroundDownload.Failure.INTEGRITY,c.failure.get());noPartial();
    }
    @Test public void advertisedCapacityRefusedBeforeBodyIsPublished()throws Exception{
        attachment("/too-large",payload,null,false);Capture c=new Capture();task("/too-large",c,1024).start();c.await();assertNull(c.result.get());assertEquals(ForegroundDownload.Failure.CAPACITY,c.failure.get());noPartial();
    }
    @Test public void unavailableDiskReserveRefusesBeforeAnyManagementRequest()throws Exception{
        AtomicInteger reached=new AtomicInteger();
        server.createContext("/no-space",e->{reached.incrementAndGet();e.sendResponseHeaders(404,-1);e.close();});
        Capture c=new Capture();
        new ForegroundDownload(address,origin+"/no-space","panel_session=owned-fixture","OwnedTest/1",directory,Runnable::run,c,1024,Long.MAX_VALUE).start();
        c.await();assertEquals(ForegroundDownload.Failure.CAPACITY,c.failure.get());
        assertNull(c.result.get());assertEquals(0,reached.get());noPartial();
    }
    @Test public void unboundedChunkedBodyCannotCrossItsLimit()throws Exception{
        attachment("/unknown-large",payload,null,true);Capture c=new Capture();task("/unknown-large",c,1024).start();c.await();assertNull(c.result.get());assertNotNull(c.failure.get());noPartial();
    }
    @Test public void truncatedResponseIsNeverComplete()throws Exception{
        server.createContext("/short",e->{e.getResponseHeaders().add("Content-Disposition","attachment; filename=short.bin");e.sendResponseHeaders(200,payload.length+50);try{e.getResponseBody().write(payload);}catch(IOException ignored){}finally{e.close();}});
        Capture c=new Capture();task("/short",c,1<<20).start();c.await();assertNull(c.result.get());assertNotNull(c.failure.get());noPartial();
    }
    @Test public void redirectNeverReachesAnotherEndpointOrForwardsItsCookie()throws Exception{
        AtomicInteger reached=new AtomicInteger();server.createContext("/target",e->{reached.incrementAndGet();e.sendResponseHeaders(200,-1);e.close();});
        server.createContext("/redirect",e->{e.getResponseHeaders().add("Location",origin+"/target");e.sendResponseHeaders(302,-1);e.close();});
        Capture c=new Capture();task("/redirect",c,1<<20).start();c.await();assertEquals(ForegroundDownload.Failure.RESPONSE,c.failure.get());assertEquals(0,reached.get());noPartial();
    }
    @Test public void loginHtmlCannotBecomeAnExportedManagementFile()throws Exception{
        server.createContext("/login",e->{e.getResponseHeaders().add("Content-Type","text/html");e.sendResponseHeaders(200,1);try{e.getResponseBody().write('x');}finally{e.close();}});
        Capture c=new Capture();task("/login",c,1<<20).start();c.await();assertEquals(ForegroundDownload.Failure.RESPONSE,c.failure.get());noPartial();
    }
    @Test public void cancellationClosesOriginalStreamAndDiscardsPartialBytes()throws Exception{
        CountDownLatch started=new CountDownLatch(1),released=new CountDownLatch(1);
        server.createContext("/slow",e->{e.getResponseHeaders().add("Content-Disposition","attachment; filename=slow.bin");e.sendResponseHeaders(200,0);
            try{e.getResponseBody().write(payload,0,64);e.getResponseBody().flush();started.countDown();released.await(5,TimeUnit.SECONDS);e.getResponseBody().write(payload);}catch(IOException ignored){}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}finally{e.close();}});
        Capture c=new Capture();ForegroundDownload t=task("/slow",c,1<<20);t.start();assertTrue(started.await(5,TimeUnit.SECONDS));t.cancel();released.countDown();c.await();assertTrue(t.cancelled());assertEquals(ForegroundDownload.Failure.CANCELLED,c.failure.get());assertNull(c.result.get());noPartial();
    }
    @Test public void crossOriginIsRejectedBeforeAnyDownloadStarts()throws Exception{
        Capture c=new Capture();try{new ForegroundDownload(address,"http://localhost:"+server.getAddress().getPort()+"/file","owned-fixture","OwnedTest",directory,Runnable::run,c);fail("cross-origin download");}catch(IllegalArgumentException expected){assertNotNull(expected);}
        noPartial();assertEquals(1,c.terminal.getCount());
    }
    @Test public void writableCacheDirectoryIsRejectedWithoutRepair()throws Exception{
        Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwxrwx---"));Capture c=new Capture();task("/file",c,1<<20).start();c.await();assertEquals(ForegroundDownload.Failure.STORAGE,c.failure.get());assertEquals(PosixFilePermissions.fromString("rwxrwx---"),Files.getPosixFilePermissions(directory));noPartial();
    }
    @Test public void anUntrustedCertificateNeverReceivesTheManagementCookie()throws Exception{
        Path fixture=Files.createTempDirectory("owned-download-TLS-fixture-");OwnedDownloadServer tls=null;AtomicInteger requestReceived=new AtomicInteger();
        try{
            Path store=fixture.resolve("fixture.p12"),log=fixture.resolve("keytool.log");
            // A new disposable test-server certificate, not a production key or
            // an added trust anchor. Client trust settings remain unchanged.
            Process keytool=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","keytool").toString(),"-genkeypair","-alias","owned-fixture","-keyalg","RSA","-keysize","2048","-storetype","PKCS12","-keystore",store.toString(),"-storepass","owned-fixture-only","-keypass","owned-fixture-only","-dname","CN=localhost","-ext","SAN=ip:127.0.0.1","-validity","1","-noprompt").redirectErrorStream(true).redirectOutput(log.toFile()).start();
            assertTrue(keytool.waitFor(20,TimeUnit.SECONDS));assertEquals(0,keytool.exitValue());
            java.security.KeyStore keys=java.security.KeyStore.getInstance("PKCS12");
            try(java.io.InputStream input=Files.newInputStream(store)){keys.load(input,"owned-fixture-only".toCharArray());}
            javax.net.ssl.KeyManagerFactory manager=javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());manager.init(keys,"owned-fixture-only".toCharArray());
            javax.net.ssl.SSLContext context=javax.net.ssl.SSLContext.getInstance("TLS");context.init(manager.getKeyManagers(),null,null);
            java.net.ServerSocket socket=context.getServerSocketFactory().createServerSocket(0,0,java.net.InetAddress.getByName("127.0.0.1"));
            tls=OwnedDownloadServer.create(socket);tls.setExecutor(executor);tls.createContext("/file",e->{requestReceived.incrementAndGet();e.sendResponseHeaders(401,-1);e.close();});tls.start();
            String target="https://127.0.0.1:"+tls.getAddress().getPort();Capture c=new Capture();
            new ForegroundDownload(PanelAddress.parse(target,false),target+"/file","panel_session=owned-fixture","OwnedTest/1",directory,Runnable::run,c,1024,0).start();
            c.await();assertEquals(ForegroundDownload.Failure.NETWORK,c.failure.get());assertNull(c.result.get());assertEquals(0,requestReceived.get());noPartial();
        }finally{
            if(tls!=null)tls.stop(0);
            try(java.util.stream.Stream<Path> files=Files.walk(fixture)){for(Path p:(Iterable<Path>)files.sorted(Comparator.reverseOrder())::iterator)Files.delete(p);}
        }
    }
    @Test public void anotherConnectionCannotQueueNetworkWorkUntilOriginalWorkerSettles()throws Exception{
        CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);AtomicInteger additional=new AtomicInteger();
        server.createContext("/held",e->{e.getResponseHeaders().add("Content-Disposition","attachment; filename=held.bin");e.sendResponseHeaders(200,0);try{e.getResponseBody().write(1);e.getResponseBody().flush();entered.countDown();release.await(5,TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}finally{e.close();}});
        server.createContext("/additional",e->{additional.incrementAndGet();e.sendResponseHeaders(404,-1);e.close();});
        Capture first=new Capture();ForegroundDownload original=task("/held",first,1024);original.start();assertTrue(entered.await(5,TimeUnit.SECONDS));
        Capture second=new Capture();task("/additional",second,1024).start();second.await();assertEquals(ForegroundDownload.Failure.BUSY,second.failure.get());assertEquals(0,additional.get());
        original.cancel();release.countDown();first.await();assertEquals(ForegroundDownload.Failure.CANCELLED,first.failure.get());
        Capture third=new Capture();task("/additional",third,1024).start();third.await();assertEquals(ForegroundDownload.Failure.RESPONSE,third.failure.get());assertEquals(1,additional.get());noPartial();
    }
}
