package icu.yunzhan.panel;

import android.content.ContentResolver;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/** Only a new document explicitly selected with ACTION_CREATE_DOCUMENT. */
final class NativeFileExport {
    enum Outcome { VERIFIED, UNVERIFIED, FAILED, CANCELLED, BUSY }
    interface Listener { void settled(Outcome outcome); }
    private final ContentResolver resolver;
    private final ForegroundDownload.Result original;
    private final Uri destination;
    private final Executor callbacks;
    private final Listener listener;
    private final AtomicBoolean started = new AtomicBoolean(), cancelled = new AtomicBoolean();
    private final CancellationSignal signal = new CancellationSignal();
    private volatile ParcelFileDescriptor current;
    NativeFileExport(ContentResolver resolver, ForegroundDownload.Result original, Uri destination, Executor callbacks, Listener listener) {
        if (destination == null || !"content".equals(destination.getScheme())) throw new IllegalArgumentException("selected document required");
        this.resolver=resolver;this.original=original;this.destination=destination;this.callbacks=callbacks;this.listener=listener;
    }
    void start() {
        if (!started.compareAndSet(false,true)) throw new IllegalStateException("original export already submitted");
        if (!NativeTransferBudget.acquire()) { callbacks.execute(()->listener.settled(Outcome.BUSY)); return; }
        try{Thread worker=new Thread(this::write,"panel-selected-document-export");worker.setDaemon(true);worker.start();}
        catch(RuntimeException | Error failure){NativeTransferBudget.release();throw failure;}
    }
    void cancel() {
        if (!cancelled.compareAndSet(false,true)) return;
        Thread closer=new Thread(()->{signal.cancel();ParcelFileDescriptor fd=current;if(fd!=null)try{fd.close();}catch(IOException ignored){}},"panel-export-cancel");closer.setDaemon(true);closer.start();
    }
    private void active() throws IOException { if(cancelled.get())throw new IOException("cancelled"); }
    private static String digest(InputStream input, long expected, OutputStream output, NativeFileExport operation) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] bytes=new byte[65536];long total=0;int count;
        while((count=input.read(bytes))!=-1){
            operation.active();if(count>expected-total)throw new IOException("unexpected document length");
            if(output!=null)output.write(bytes,0,count);digest.update(bytes,0,count);total+=count;
        }
        operation.active();if(total!=expected)throw new IOException("incomplete document");return ForegroundDownload.hex(digest.digest());
    }
    private void write() {
        Outcome outcome=Outcome.FAILED;boolean written=false;
        try {
            active();if(!Files.isRegularFile(original.path,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(original.path)||Files.size(original.path)!=original.bytes)throw new IOException("private source changed");
            try(InputStream source=Files.newInputStream(original.path,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)){
                active();ParcelFileDescriptor fd=resolver.openFileDescriptor(destination,"w",signal);if(fd==null)throw new IOException("document unavailable");current=fd;
                try(OutputStream target=new ParcelFileDescriptor.AutoCloseOutputStream(fd)){
                    String actual=digest(source,original.bytes,target,this);if(!actual.equals(original.sha256))throw new IOException("private source changed");target.flush();active();
                }finally{current=null;}
            }
            written=true;active();
            // A provider accepting a closed stream is distinct from reading
            // back the exact bytes. Never claim verified cloud persistence.
            ParcelFileDescriptor fd=resolver.openFileDescriptor(destination,"r",signal);if(fd==null)throw new IOException("document not readable");current=fd;
            try(InputStream saved=new ParcelFileDescriptor.AutoCloseInputStream(fd)){
                if(!digest(saved,original.bytes,null,this).equals(original.sha256))throw new IOException("selected document differs");
            }finally{current=null;}
            active();outcome=Outcome.VERIFIED;
        } catch(Exception failure){outcome=cancelled.get()?Outcome.CANCELLED:written?Outcome.UNVERIFIED:Outcome.FAILED;}
        finally{ParcelFileDescriptor fd=current;current=null;if(fd!=null)try{fd.close();}catch(IOException ignored){}NativeTransferBudget.release();}
        Outcome result=cancelled.get()?Outcome.CANCELLED:outcome;callbacks.execute(()->listener.settled(result));
    }
}
