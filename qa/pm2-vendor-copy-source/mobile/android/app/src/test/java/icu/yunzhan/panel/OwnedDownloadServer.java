package icu.yunzhan.panel;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;

/** A loopback HTTP fixture using APIs also present in Android's Java API. */
final class OwnedDownloadServer {
    interface Handler { void handle(Exchange exchange) throws IOException; }
    static final class Headers {
        private final Map<String,String> values=new java.util.LinkedHashMap<>();
        void add(String key,String value){values.put(key.toLowerCase(Locale.ROOT),value);}
        String getFirst(String key){return values.get(key.toLowerCase(Locale.ROOT));}
    }
    static final class Exchange {
        private final Socket socket;
        private final Headers request, response=new Headers();
        private OutputStream body;
        private boolean chunked,closed;
        Exchange(Socket socket,Headers headers){this.socket=socket;this.request=headers;}
        Headers getRequestHeaders(){return request;}
        Headers getResponseHeaders(){return response;}
        void sendResponseHeaders(int status,long length)throws IOException{
            OutputStream raw=socket.getOutputStream();chunked=length==0;
            StringBuilder header=new StringBuilder("HTTP/1.1 "+status+" "+(status==200?"OK":"Response")+"\r\nConnection: close\r\n");
            for(Map.Entry<String,String> row:response.values.entrySet())header.append(row.getKey()).append(": ").append(row.getValue()).append("\r\n");
            header.append(chunked?"Transfer-Encoding: chunked\r\n":"Content-Length: "+Math.max(0,length)+"\r\n");header.append("\r\n");
            raw.write(header.toString().getBytes(StandardCharsets.US_ASCII));raw.flush();
            body=new OutputStream(){
                @Override public void write(int value)throws IOException{write(new byte[]{(byte)value},0,1);}
                @Override public void write(byte[] bytes,int start,int count)throws IOException{
                    if(chunked)raw.write((Integer.toHexString(count)+"\r\n").getBytes(StandardCharsets.US_ASCII));
                    raw.write(bytes,start,count);if(chunked)raw.write(new byte[]{13,10});
                }
                @Override public void flush()throws IOException{raw.flush();}
            };
        }
        OutputStream getResponseBody(){if(body==null)throw new IllegalStateException("response headers missing");return body;}
        void close(){
            if(closed)return;closed=true;
            try{if(chunked&&body!=null)socket.getOutputStream().write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));}catch(IOException ignored){}
            try{socket.close();}catch(IOException ignored){}
        }
    }
    private final ServerSocket socket;
    private final Map<String,Handler> handlers=new ConcurrentHashMap<>();
    private final Map<Socket,Boolean> clients=new ConcurrentHashMap<>();
    private ExecutorService executor;
    private Thread acceptor;
    private volatile boolean stopped;
    private OwnedDownloadServer(ServerSocket socket){this.socket=socket;}
    static OwnedDownloadServer create(InetSocketAddress address,int backlog)throws IOException{
        ServerSocket socket=new ServerSocket();socket.bind(address,backlog);return new OwnedDownloadServer(socket);
    }
    static OwnedDownloadServer create(ServerSocket socket){return new OwnedDownloadServer(socket);}
    void setExecutor(ExecutorService executor){this.executor=executor;}
    InetSocketAddress getAddress(){return(InetSocketAddress)socket.getLocalSocketAddress();}
    void createContext(String path,Handler handler){if(handlers.putIfAbsent(path,handler)!=null)throw new IllegalArgumentException("fixture path reused");}
    void start(){
        acceptor=new Thread(()->{
            while(!stopped)try{Socket client=socket.accept();client.setSoTimeout(10000);clients.put(client,Boolean.TRUE);executor.execute(()->serve(client));}
            catch(IOException failure){if(!stopped)throw new IllegalStateException(failure);}
        },"owned-loopback-download-acceptor");acceptor.setDaemon(true);acceptor.start();
    }
    private void serve(Socket client){
        Exchange exchange=null;
        try{
            BufferedReader input=new BufferedReader(new InputStreamReader(client.getInputStream(),StandardCharsets.US_ASCII));
            String line=input.readLine();if(line==null||line.length()>8192||!line.startsWith("GET "))return;
            String[] request=line.split(" ",3);if(request.length!=3)return;
            Headers headers=new Headers();int bytes=0;
            while((line=input.readLine())!=null&&!line.isEmpty()){
                bytes+=line.length();if(bytes>32768)throw new IOException("fixture header budget");int colon=line.indexOf(':');if(colon<1)throw new IOException("fixture header");headers.add(line.substring(0,colon),line.substring(colon+1).trim());
            }
            exchange=new Exchange(client,headers);Handler handler=handlers.get(request[1]);
            if(handler==null){exchange.sendResponseHeaders(404,-1);return;}handler.handle(exchange);
        }catch(IOException ignored){}finally{if(exchange!=null)exchange.close();try{client.close();}catch(IOException ignored){}clients.remove(client);}
    }
    void stop(int ignored){
        stopped=true;try{socket.close();}catch(IOException failure){throw new IllegalStateException(failure);}
        for(Socket client:clients.keySet())try{client.close();}catch(IOException ignoredFailure){}
        if(acceptor!=null)try{acceptor.join(3000);}catch(InterruptedException failure){Thread.currentThread().interrupt();}
    }
}
