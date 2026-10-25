package com.subgraph.orchid.http.get;

import com.subgraph.orchid.http.TorSocketStream;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class TorSocketHttpsGet extends TorSocketStream {
    
    private TorSocketHttpsGet(String url, SSLContext sslContext){
        super(url, sslContext);
    }
    
    public static TorSocketHttpsGet getInstance(String url, SSLContext sslContext){
        return new TorSocketHttpsGet(url, sslContext);
    }
    
    @Override
    public void executeRequest() throws Exception {
        try{
            try{
                openTlsSocket();
            } catch(IOException e){
                throw new Exception("TLS certificate check failed. Either add the server certificate with ApplicationProperties.setAdditionalSslCertificates() or, only if you accept that a malicious exit relay can read and modify the connection, configure [TorRequest].setEnforceSslCertificates(false)", e);
            }
            inputStream = sslSocket.getInputStream();
            writeRequest(sslSocket.getOutputStream(),
                    "GET "+getPath()+getQuery()+" HTTP/1.0\r\n" +
                    "Host: "+getHost()+"\r\n" +
                    "Connection: close\r\n" +
                    "\r\n");
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
