package com.subgraph.orchid.http.post;

import com.subgraph.orchid.http.NameValuePair;
import com.subgraph.orchid.http.TorClientFactory;
import com.subgraph.orchid.http.TorSocketStream;
import com.subgraph.orchid.TorClient;
import java.nio.charset.Charset;
import java.util.List;

public class TorSocketHttpPost extends TorSocketStream {
    
    protected TorSocketHttpPost(String url, List<NameValuePair> params){
        super(url, params, null);
    }
    
    public static TorSocketHttpPost getInstance(String url, List<NameValuePair> params){
        return new TorSocketHttpPost(url, params);
    }
    
    /*
     * Connects to the port in the URL (80 when there is none); up to 2.1.1
     * this was always 80.  Content-Length counts the bytes of the body, which
     * is sent without the trailing newline that PrintWriter#println added.
     */
    @Override
    public void executeRequest() throws Exception{
        TorClient client = TorClientFactory.getTorClient();
        socket = client.getSocketFactory().createSocket(getHost(), getPort(80));
        inputStream = socket.getInputStream();
        final byte[] body = getParams().getBytes(Charset.forName("UTF-8"));
        writeRequest(socket.getOutputStream(),
                "POST "+getPath()+getQuery()+" HTTP/1.0\r\n" +
                "Host: "+getHostHeader(80)+"\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: "+body.length+"\r\n" +
                "Connection: close\r\n" +
                "\r\n");
        socket.getOutputStream().write(body);
        socket.getOutputStream().flush();
    }
}
