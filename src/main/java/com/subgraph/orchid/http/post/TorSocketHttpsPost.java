package com.subgraph.orchid.http.post;

import com.subgraph.orchid.http.NameValuePair;
import com.subgraph.orchid.http.TorSocketStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
import javax.net.ssl.SSLContext;

public class TorSocketHttpsPost extends TorSocketStream {
    
    private TorSocketHttpsPost(String url, List<NameValuePair> params, SSLContext sslContext){
        super(url, params, sslContext);
    }
    
    public static TorSocketHttpsPost getInstance(String url, List<NameValuePair> params, SSLContext sslContext){
        return new TorSocketHttpsPost(url, params, sslContext);
    }
    
    /*
     * Connects to port 443 (or the URL's port).  Up to 2.1.0 this connected
     * to port 80 and spoke TLS there, so HTTPS POST requests did not work.
     */
    @Override
    public void executeRequest() throws Exception{
        try{
            try{
                openTlsSocket();
            } catch(IOException e){
                throw new Exception("TLS certificate check failed. Either add the server certificate with ApplicationProperties.setAdditionalSslCertificates() or, only if you accept that a malicious exit relay can read and modify the connection, configure [TorRequest].setEnforceSslCertificates(false)", e);
            }
            inputStream = sslSocket.getInputStream();
            final byte[] body = getParams().getBytes(Charset.forName("UTF-8"));
            writeRequest(sslSocket.getOutputStream(),
                    "POST "+getPath()+getQuery()+" HTTP/1.0\r\n" +
                    "Host: "+getHostHeader(443)+"\r\n" +
                    "Content-Type: application/x-www-form-urlencoded\r\n" +
                    "Content-Length: "+body.length+"\r\n" +
                    "Connection: close\r\n" +
                    "\r\n");
            sslSocket.getOutputStream().write(body);
            sslSocket.getOutputStream().flush();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int character;
            try{
                while((character = inputStream.read())!=-1){
                    byteArrayOutputStream.write(character);
                }
            } catch(Exception e){
                //swallow
                byteArrayOutputStream.write(-1);
            } finally{
                try{
                    inputStream.close();
                } catch(IOException e){
                    //Could not close stream
                }
            }
            inputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        } finally{
            if(sslSocket != null){
                sslSocket.close();
            }
            if(socket != null){
                socket.close();
            }
        }
    }
}
