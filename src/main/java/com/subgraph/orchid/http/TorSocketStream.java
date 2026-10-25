package com.subgraph.orchid.http;

import com.subgraph.orchid.sockets.sslengine.SSLEngineSSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.util.List;
import java.util.ArrayList;
import javax.net.ssl.SSLContext;

public abstract class TorSocketStream extends InputStream {
    protected final String url;
    protected final List<NameValuePair> params;
    protected InputStream inputStream;
    protected int responseCode;
    protected Socket socket;
    protected SSLEngineSSLSocket sslSocket;
    protected final SSLContext sslContext;
    
    protected TorSocketStream(String url, SSLContext sslContext){
        this.url = url;
        this.params = new ArrayList();
        this.sslContext = sslContext;
    }
    
    protected TorSocketStream(String url, List<NameValuePair> params, SSLContext sslContext){
        this.url = url;
        this.params = params;
        this.sslContext = sslContext;
    }

    public abstract void executeRequest() throws Exception;

    /**
     * The port given in the URL, or <code>defaultPort</code> if there is none.
     */
    protected int getPort(int defaultPort){
        try{
            final int port = new URI(url.replace(" ", "%20")).getPort();
            return (port > 0) ? port : defaultPort;
        } catch(Exception e){
            return defaultPort;
        }
    }

    /**
     * The value of the Host header: the host, followed by ":port" when the
     * URL names a port other than <code>defaultPort</code> (RFC 9110 section
     * 7.2).  Without the port, a server on a non-default port may answer for
     * the wrong virtual host or reject the request.
     */
    protected String getHostHeader(int defaultPort){
        final int port = getPort(defaultPort);
        return (port == defaultPort) ? getHost() : getHost() + ":" + port;
    }

    /**
     * Open a stream through Tor to the URL's host and complete the TLS
     * handshake, checking that the certificate is valid for that host,
     * before anything of the request is sent.  Sets {@link #socket} and
     * {@link #sslSocket}.
     *
     * @throws IOException if the connection or the handshake fails,
     *         including when the certificate is not trusted or was issued
     *         for another name.
     */
    protected SSLEngineSSLSocket openTlsSocket() throws IOException {
        final String host = getHost();
        if(host == null || host.isEmpty()){
            throw new IOException("No host name in URL "+ url);
        }
        if(sslContext == null){
            throw new IOException("No TLS context available");
        }
        final int port = getPort(443);
        socket = TorClientFactory.getTorClient().getSocketFactory().createSocket(host, port);
        sslSocket = new SSLEngineSSLSocket(socket, sslContext, host, port);
        sslSocket.startHandshake();
        if(!sslSocket.getSession().isValid()){
            throw new IOException("TLS session with "+ host +" is not valid");
        }
        return sslSocket;
    }

    /**
     * Write an HTTP request.  Unlike a PrintWriter, this reports I/O errors
     * (a failed TLS handshake among them) instead of hiding them.
     */
    protected static void writeRequest(OutputStream out, String request) throws IOException {
        out.write(request.getBytes(Charset.forName("UTF-8")));
        out.flush();
    }
    
    protected String getHost(){
        try{
            return new URI(url.replace(" ", "%20")).getHost();
        } catch(Exception e){
            //swallow
            return null;
        }
    }
    
    protected String getPath(){
        try{
            String path = new URI(url.replace(" ", "%20")).getPath();
            if(path.isEmpty()){
                return "/";
            } else{
                return path;
            }
        } catch(Exception e){
            //swallow
            return "";
        }
    }
    
    protected String getParams(){
        if(params==null){
            return "";
        } else{
            StringBuilder sb = new StringBuilder();
            String ampersand = "";
            for(NameValuePair param : params){
                String name = "";
                if(param.getName()!=null){
                    try{
                        name = URLEncoder.encode(param.getName(), "UTF-8");
                    } catch(Exception e){
                        //swallow
                    }
                }
                String value = "";
                if(param.getValue()!=null){
                    try{
                        value = URLEncoder.encode(param.getValue(), "UTF-8");
                    } catch(Exception e){
                        //swallow
                    }
                }
                sb.append(ampersand).append(name).append("=").append(value);
                ampersand = "&";
            }
            return sb.toString();
        }
    }
    
    protected String getQuery(){
        try{
            String query = new URI(url.replace(" ", "+")).getQuery();
            if(query.isEmpty()){
                return "";
            } else {
                return "?"+query;
            }
        } catch(Exception e){
            //swallow
            return "";
        }
    }

    @Override
    public int read() throws IOException{
        if(inputStream==null){
            return -1;
        }
        try{
            return inputStream.read();
        } catch(Exception e){
            return -1;
        }
    }

    @Override
    public void close() {
        try{
            inputStream.close();
        } catch(IOException e){
            //Could not close input stream. Probably already closed.
        } catch(NullPointerException e){
            //The request probubally failed 
        } finally {
            try{
                if(socket!=null){
                    socket.close();
                }
            } catch(IOException e){
                //Could not close socket
            }
        }
    }
}