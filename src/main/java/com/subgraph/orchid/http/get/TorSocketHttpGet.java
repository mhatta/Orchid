package com.subgraph.orchid.http.get;

import com.subgraph.orchid.http.TorClientFactory;
import com.subgraph.orchid.http.TorSocketStream;
import com.subgraph.orchid.TorClient;

public class TorSocketHttpGet extends TorSocketStream {
    
    private TorSocketHttpGet(String url){
        super(url, null);
    }
    
    public static TorSocketHttpGet getInstance(String url){
        return new TorSocketHttpGet(url);
    }
    
    /*
     * Connects to the port in the URL (80 when there is none); up to 2.1.1
     * this was always 80.  The request is written with CRLF line ends and
     * through an OutputStream, so that write errors are reported instead of
     * being hidden by a PrintWriter.
     */
    @Override
    public void executeRequest() throws Exception{
        TorClient client = TorClientFactory.getTorClient();
        socket = client.getSocketFactory().createSocket(getHost(), getPort(80));
        inputStream = socket.getInputStream();
        writeRequest(socket.getOutputStream(),
                "GET "+getPath()+getQuery()+" HTTP/1.0\r\n" +
                "Host: "+getHostHeader(80)+"\r\n" +
                "Connection: close\r\n" +
                "\r\n");
    }
}
