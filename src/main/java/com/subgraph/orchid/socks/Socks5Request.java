package com.subgraph.orchid.socks;

import java.net.Socket;

import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;

public class Socks5Request extends SocksRequest {
	final static int SOCKS5_VERSION = 5;
	final static int SOCKS5_AUTH_NONE = 0;
	final static int SOCKS5_AUTH_USERPASS = 2;
	final static int SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF;
	/* RFC 1929 */
	final static int USERPASS_VERSION = 1;
	final static int USERPASS_SUCCESS = 0;
	final static int USERPASS_FAILURE = 1;
	final static int SOCKS5_COMMAND_CONNECT = 1;
	final static int SOCKS5_COMMAND_RESOLV = 0xF0;
	final static int SOCKS5_COMMAND_RESOLV_PTR = 0xF1;
	final static int SOCKS5_ADDRESS_IPV4 = 1;
	final static int SOCKS5_ADDRESS_HOSTNAME = 3;
	final static int SOCKS5_ADDRESS_IPV6 = 4;
	final static int SOCKS5_STATUS_SUCCESS = 0;
	final static int SOCKS5_STATUS_FAILURE = 1;
	final static int SOCKS5_STATUS_CONNECTION_REFUSED = 5;
	final static int SOCKS5_STATUS_COMMAND_NOT_SUPPORTED = 7;
	final static int SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED = 8;
	
	private int command;
	private int addressType;
	private byte[] addressBytes = new byte[0];
	private byte[] portBytes = new byte[0];
	/* Set when the request names an address type Orchid cannot connect to (IPv6, or unknown). */
	private boolean addressTypeUnsupported;
	
	Socks5Request(TorConfig config, Socket socket) {
		super(config, socket);
	}
	
	public boolean isConnectRequest() {
		return command == SOCKS5_COMMAND_CONNECT;
	}
	
	public int getCommandCode() {
		return command;
	}

	private String addressBytesToHostname() {
		if(addressType != SOCKS5_ADDRESS_HOSTNAME)
			throw new TorException("SOCKS 4 request is not a hostname request");
		final StringBuilder sb = new StringBuilder();
		for(int i = 1; i < addressBytes.length; i++) {
			char c = (char) (addressBytes[i] & 0xFF);
			sb.append(c);
		}
		return sb.toString();
	}
	
	public void readRequest() throws SocksRequestException {
		if(!processAuthentication()) {
			throw new SocksRequestException("Failed to negotiate authentication");
		}
		if(readByte() != SOCKS5_VERSION)
			throw new SocksRequestException();

		command = readByte();
		readByte(); // Reserved
		addressType = readByte();
		addressBytes = readAddressBytes();
		portBytes = readPortData();
		if(addressType == SOCKS5_ADDRESS_IPV4)
			setIPv4AddressData(addressBytes);
		else if(addressType == SOCKS5_ADDRESS_HOSTNAME)
			setHostname(addressBytesToHostname());
		else {
			// IPv6: exit streams to IPv6 addresses are not supported yet.
			setAddressOnly();
			addressTypeUnsupported = true;
			throw new SocksRequestException("SOCKS 5 address type "+ addressType +" is not supported");
		}
		setPortData(portBytes);		
	}
	
	public void sendConnectionRefused() throws SocksRequestException {
		sendResponse(SOCKS5_STATUS_CONNECTION_REFUSED);
	}

	public void sendError(boolean isUnsupportedCommand) throws SocksRequestException  {
		if(addressTypeUnsupported) {
			sendResponse(SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED);
		} else if(isUnsupportedCommand) {
			sendResponse(SOCKS5_STATUS_COMMAND_NOT_SUPPORTED);
		} else {
			sendResponse(SOCKS5_STATUS_FAILURE);
		}
	}
	
	public void sendSuccess() throws SocksRequestException {
		sendResponse(SOCKS5_STATUS_SUCCESS);
	}
	
	private void sendResponse(int status) throws SocksRequestException {
		final int responseLength = 4 + addressBytes.length + portBytes.length;
		final byte[] response = new byte[responseLength];
		response[0] = SOCKS5_VERSION;
		response[1] = (byte) status;
		response[2] = 0;
		response[3] = (byte) addressType;
		System.arraycopy(addressBytes, 0, response, 4, addressBytes.length);
		System.arraycopy(portBytes, 0, response, 4 + addressBytes.length, portBytes.length);
		socketWrite(response);
	}
	
	/*
	 * Username/password authentication (RFC 1929) is chosen whenever the
	 * client offers it, as Tor does, so that the credentials can isolate
	 * its streams.  "No authentication" is accepted only when no SOCKS
	 * password is configured (TorConfig#setSocksPassword()).
	 */
	private boolean processAuthentication() throws SocksRequestException {
		final int nmethods = readByte();
		boolean foundAuthNone = false;
		boolean foundUserPass = false;
		for(int i = 0; i < nmethods; i++) {
			final int meth = readByte();
			if(meth == SOCKS5_AUTH_NONE) {
				foundAuthNone = true;
			} else if(meth == SOCKS5_AUTH_USERPASS) {
				foundUserPass = true;
			}
		}

		if(foundUserPass) {
			sendAuthenticationResponse(SOCKS5_AUTH_USERPASS);
			return processUserPassAuthentication();
		} else if(foundAuthNone && !ProxyAuthentication.isRequired(getConfig())) {
			sendAuthenticationResponse(SOCKS5_AUTH_NONE);
			return true;
		} else {
			sendAuthenticationResponse(SOCKS5_AUTH_NO_ACCEPTABLE);
			return false;
		}
	}

	private boolean processUserPassAuthentication() throws SocksRequestException {
		if(readByte() != USERPASS_VERSION) {
			throw new SocksRequestException("Bad username/password authentication version");
		}
		final byte[] username = readLengthPrefixed();
		final byte[] password = readLengthPrefixed();
		final String profile = ProxyAuthentication.authenticate(getConfig(), password);
		if(profile == null) {
			sendUserPassResponse(USERPASS_FAILURE);
			return false;
		}
		setProfile(profile);
		sendUserPassResponse(USERPASS_SUCCESS);
		setIsolationKey("socks5", username, password);
		return true;
	}

	private byte[] readLengthPrefixed() throws SocksRequestException {
		final byte[] data = new byte[readByte()];
		readAll(data);
		return data;
	}

	private void sendUserPassResponse(int status) throws SocksRequestException {
		socketWrite(new byte[] { (byte) USERPASS_VERSION, (byte) status });
	}

	private void sendAuthenticationResponse(int method) throws SocksRequestException {
		final byte[] response = new byte[2];
		response[0] = SOCKS5_VERSION;
		response[1] = (byte) method;
		socketWrite(response);
	}

	private byte[] readAddressBytes() throws SocksRequestException {
		switch(addressType) {
		case SOCKS5_ADDRESS_IPV4:
			return readIPv4AddressData();
		case SOCKS5_ADDRESS_IPV6:
			return readIPv6AddressData();
		case SOCKS5_ADDRESS_HOSTNAME:
			return readHostnameData();
		default:
			/*
			 * The length of an unknown address is unknown too, so the rest
			 * of the request cannot be read.  Answer with an IPv4-shaped
			 * reply (RFC 1928 requires an address in it) and close.
			 */
			addressTypeUnsupported = true;
			addressType = SOCKS5_ADDRESS_IPV4;
			addressBytes = new byte[4];
			portBytes = new byte[2];
			throw new SocksRequestException("Unknown SOCKS 5 address type");
		}
	}
	
	private byte[] readHostnameData() throws SocksRequestException {
		final int length = readByte();
		final byte[] addrData = new byte[length + 1];
		addrData[0] = (byte) length;
		readAll(addrData, 1, length);
		return addrData;
	}
}
