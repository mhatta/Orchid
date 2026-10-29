package com.subgraph.orchid.directory.downloader;

import com.subgraph.orchid.ApplicationProperties;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.logging.Logger;

public class HttpConnection {
    private static final Logger logger = Logger.getInstance(HttpConnection.class);
    private final static Charset CHARSET = Charset.forName("ISO-8859-1");

    private final static String HTTP_RESPONSE_REGEX = "HTTP/1\\.(\\d) (\\d+) (.*)";
    private final static String CONTENT_LENGTH_HEADER = "Content-Length";
    private final static String CONTENT_ENCODING_HEADER = "Content-Encoding";
    private final static String COMPRESSION_SUFFIX = ".z";

    /*
     * Limits on what a directory server can make Orchid read (Tor's own
     * limits are similar: MAX_HEADERS_SIZE and MAX_DIR_DL_SIZE).  Without
     * them a malicious or broken directory cache, or an HSDir, could exhaust
     * the heap with a huge Content-Length, an endless body or line, or a
     * small compressed body that inflates to gigabytes, and bring down the
     * application Orchid runs in.
     */
    /** Longest status or header line, in bytes. */
    final static int MAX_LINE_LENGTH = 8192;
    /** Most bytes of status line and headers together. */
    final static int MAX_HEADERS_SIZE = 50000;
    /** Default limit on a response body, before and after decompression. */
    public final static int DEFAULT_MAX_BODY_SIZE = 16 * 1024 * 1024;
    private final String hostname;
    private final Stream stream;
    private final InputStream input;
    private final OutputStream output;
    private final Map<String, String> headers;
    private final boolean useCompression;
    private final int maxBodySize;
    private int headerBytesRead;
    private int responseCode;
    private boolean bodyCompressed;
    private String responseMessage;
    private ByteBuffer messageBody;

    public HttpConnection(Stream stream) {
        this(stream, ApplicationProperties.getUseCompression());
    }

    public HttpConnection(Stream stream, boolean useCompression) {
        this(stream, useCompression, DEFAULT_MAX_BODY_SIZE);
    }

    /**
     * @param maxBodySize The largest response body accepted, in bytes, both
     *        as received and after decompression.
     */
    public HttpConnection(Stream stream, boolean useCompression, int maxBodySize) {
        this.maxBodySize = maxBodySize;
        this.hostname = getHostnameFromStream(stream);
        this.stream = stream;
        this.headers = new HashMap<String, String>();
        this.input = stream.getInputStream();
        this.output = stream.getOutputStream();
        this.useCompression = useCompression;
    }

    private static String getHostnameFromStream(Stream stream) {
        final StringBuilder sb = new StringBuilder();
        final Router r = stream.getCircuit().getFinalCircuitNode().getRouter();
        if(r == null) {
            return null;
        }
        sb.append(r.getAddress().toString());
        if(r.getOnionPort() != 80) {
            sb.append(":");
            sb.append(r.getOnionPort());
        }
        return sb.toString();
    }

    public void sendGetRequest(String request) throws IOException {
        final StringBuilder sb = new StringBuilder();
        sb.append("GET ");
        sb.append(request);
        if(useCompression && !request.endsWith(COMPRESSION_SUFFIX)) {
            sb.append(COMPRESSION_SUFFIX);
        }
        sb.append(" HTTP/1.0\r\n");
        if(hostname != null) {
            sb.append("Host: "+ hostname +"\r\n");
        }
        sb.append("\r\n");
        logger.debug("-----------------\r\n"+sb.toString()+"-----------------");
        final String requestLine = sb.toString();
        output.write(requestLine.getBytes(CHARSET));
        output.flush();
    }

    public String getHost() {
        if(hostname != null) {
            return hostname;
        } else {
            return "(none)";
        }
    }

    public void readResponse() throws IOException, DirectoryRequestFailedException {
        readStatusLine();
        readHeaders();
        readBody();
    }

    public int getStatusCode() {
        return responseCode;
    }

    public String getStatusMessage() {
        return responseMessage;
    }

    public ByteBuffer getMessageBody() {
        return messageBody;
    }

    public void close() {
        if(stream == null) {
            return;
        }
        stream.close();
    }

    private void readStatusLine() throws IOException, DirectoryRequestFailedException {
        final String line = nextResponseLine();	
        final Pattern p = Pattern.compile(HTTP_RESPONSE_REGEX);
        final Matcher m = p.matcher(line);
        if(!m.find() || m.groupCount() != 3) 
                throw new DirectoryRequestFailedException("Error parsing HTTP response line: "+ line);

        try {
            int n1 = Integer.parseInt(m.group(1));
            int n2 = Integer.parseInt(m.group(2));
            if( (n1 != 0 && n1 != 1) || (n2 < 100 || n2 >= 600)){
                throw new DirectoryRequestFailedException("Failed to parse header: "+ line);
            }
            responseCode = n2;
            responseMessage = m.group(3);
        } catch(NumberFormatException e) {
            throw new DirectoryRequestFailedException("Failed to parse header: "+ line);
        }
    }

    private void readHeaders() throws IOException, DirectoryRequestFailedException {
        headers.clear();
        while(true) {
            final String line = nextResponseLine();
            if(line.length() == 0){
                return;
            }
            final String[] args = line.split(": ", 2);
            if(args.length != 2){
                throw new DirectoryRequestFailedException("Failed to parse HTTP header: "+ line);
            }
            headers.put(args[0], args[1]);
        }
    }

    private String nextResponseLine() throws IOException, DirectoryRequestFailedException {
        final String line = readInputLine();
        if(line == null) {
            throw new DirectoryRequestFailedException("Unexpected EOF reading HTTP response");
        }
        return line;
    }

    private void readBody() throws IOException, DirectoryRequestFailedException {
        processContentEncodingHeader();

        if(headers.containsKey(CONTENT_LENGTH_HEADER)) { 
            readBodyFromContentLength();
        } else { 
            readBodyUntilEOF();
        }
    }
	
    private void processContentEncodingHeader() throws DirectoryRequestFailedException {
        final String encoding = headers.get(CONTENT_ENCODING_HEADER);
        if(encoding == null || encoding.equals("identity")) {
            bodyCompressed = false;
        } else if(encoding.equals("deflate") || encoding.equals("x-deflate")){
            bodyCompressed = true;
        } else{
            throw new DirectoryRequestFailedException("Unrecognized content encoding: "+ encoding);
        }
    }
	
    private void readBodyFromContentLength() throws IOException, DirectoryRequestFailedException {
        final String value = headers.get(CONTENT_LENGTH_HEADER).trim();
        final long bodyLength;
        try {
            bodyLength = Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new DirectoryRequestFailedException("Invalid Content-Length: "+ value);
        }
        if(bodyLength < 0 || bodyLength > maxBodySize) {
            throw new DirectoryRequestFailedException("Content-Length "+ bodyLength +" is outside the accepted range (0 to "+ maxBodySize +" bytes)");
        }
        final byte[] bodyBuffer = new byte[(int) bodyLength];
        readAll(bodyBuffer);
        messageBody = bytesToBody(bodyBuffer);
    }
	
    private void readBodyUntilEOF() throws IOException, DirectoryRequestFailedException {
        final byte[] bodyBuffer = readToEOF();
        messageBody = bytesToBody(bodyBuffer);
    }
	
    private ByteBuffer bytesToBody(byte[] bs) throws IOException, DirectoryRequestFailedException {
        if(bodyCompressed) {
            return ByteBuffer.wrap(decompressBuffer(bs));
        } else {
            return ByteBuffer.wrap(bs);
        }
    }
	
    private byte[] decompressBuffer(byte[] buffer) throws IOException, DirectoryRequestFailedException {
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Inflater decompressor = new Inflater();
        final byte[] decompressBuffer = new byte[4096];
        decompressor.setInput(buffer);
        int n;
        try {
            while((n = decompressor.inflate(decompressBuffer)) != 0) {
                if(output.size() + n > maxBodySize) {
                    throw new DirectoryRequestFailedException("Decompressed response body exceeds "+ maxBodySize +" bytes");
                }
                output.write(decompressBuffer, 0, n);
            }
            return output.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("Error decompressing http body: "+ e);
        } finally {
            decompressor.end();
        }
    }
	
    private byte[] readToEOF() throws IOException, DirectoryRequestFailedException {
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final byte[] buffer = new byte[2048];
        int n;
        while( (n = input.read(buffer, 0, buffer.length)) != -1) {
            if(output.size() + n > maxBodySize) {
                throw new DirectoryRequestFailedException("Response body exceeds "+ maxBodySize +" bytes");
            }
            output.write(buffer, 0, n);
        }
        return output.toByteArray();
    }

    private void readAll(byte[] buffer) throws IOException {
        int offset = 0;
        int remaining = buffer.length;
        while(remaining > 0) {
            int n = input.read(buffer, offset, remaining);
            if(n == -1) {
                throw new IOException("Unexpected early EOF reading HTTP body");
            }
            offset += n;
            remaining -= n;
        }
    }
	
    private String readInputLine() throws IOException, DirectoryRequestFailedException {
        final StringBuilder sb = new StringBuilder();
        int c;
        while((c = input.read()) != -1) {
            headerBytesRead += 1;
            if(headerBytesRead > MAX_HEADERS_SIZE) {
                throw new DirectoryRequestFailedException("HTTP response headers exceed "+ MAX_HEADERS_SIZE +" bytes");
            }
            if(c == '\n') {
                return sb.toString();
            } else if(c != '\r') {
                if(sb.length() >= MAX_LINE_LENGTH) {
                    throw new DirectoryRequestFailedException("HTTP response line longer than "+ MAX_LINE_LENGTH +" bytes");
                }
                sb.append((char) c);
            }
        }
        return (sb.length() == 0) ? (null) : (sb.toString());
    }
}
