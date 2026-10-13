package com.subgraph.orchid.circuits.hs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.DirectoryCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.circuits.CircuitManagerImpl;
import com.subgraph.orchid.directory.downloader.DirectoryRequestFailedException;
import com.subgraph.orchid.directory.downloader.HttpConnection;
import com.subgraph.orchid.encoders.Base64;
import com.subgraph.orchid.logging.Logger;

/**
 * Fetches a version 3 onion service descriptor from the responsible HSDirs
 * over an anonymous directory stream:
 * <pre>
 *   GET /tor/hs/3/&lt;base64 blinded public key&gt;
 * </pre>
 * (rend-spec-v3 section 2.2.4 and 2.2.5).
 */
public class HSV3DescriptorDownloader {
	private static final Logger logger = Logger.getInstance(HSV3DescriptorDownloader.class);
	private static final int DIRECTORY_STREAM_TIMEOUT = 15000;

	private final HiddenService hiddenService;
	private final CircuitManagerImpl circuitManager;
	private final List<Router> directories;

	public HSV3DescriptorDownloader(HiddenService hiddenService, CircuitManagerImpl circuitManager, List<Router> directories) {
		this.hiddenService = hiddenService;
		this.circuitManager = circuitManager;
		this.directories = directories;
	}

	public HSV3Descriptor downloadDescriptor() {
		for(Router d: directories) {
			final HSV3Descriptor descriptor = downloadDescriptorFrom(d);
			if(descriptor != null) {
				return descriptor;
			}
		}
		return null;
	}

	static String descriptorPath(byte[] blindedPublicKey) {
		String b64 = new String(Base64.encode(blindedPublicKey));
		while(b64.endsWith("=")) {
			b64 = b64.substring(0, b64.length() - 1);
		}
		return "/tor/hs/3/"+ b64;
	}

	private HSV3Descriptor downloadDescriptorFrom(Router dir) {
		logger.debug("Downloading v3 descriptor for "+ hiddenService.getOnionAddressForLogging() + " from "+ dir);
		Stream stream = null;
		try {
			stream = openHSDirectoryStream(dir);
			/* The ".z" compression suffix is not supported for HS descriptors (rend-spec-v3 2.2.4) */
			final HttpConnection http = new HttpConnection(stream, false);
			http.sendGetRequest(descriptorPath(hiddenService.getBlindedPublicKey()));
			http.readResponse();
			if(http.getStatusCode() == 200) {
				return parseDocument(dir, http.getMessageBody());
			} else {
				logger.debug("v3 descriptor download for "+ hiddenService.getOnionAddressForLogging() + " from "+ dir + " failed with status "+ http.getStatusCode());
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (TimeoutException e) {
			logger.debug("Timeout downloading v3 descriptor from "+ dir);
		} catch (IOException e) {
			logger.info("IOException downloading v3 descriptor from "+ dir + " : "+ e);
		} catch (OpenFailedException e) {
			logger.info("Failed to open stream to HSDir "+ dir + " : "+ e.getMessage());
		} catch (DirectoryRequestFailedException e) {
			logger.info("Directory request to HSDir "+ dir + " failed: "+ e.getMessage());
		} finally {
			if(stream != null) {
				stream.close();
				stream.getCircuit().markForClose();
			}
		}
		return null;
	}

	private Stream openHSDirectoryStream(Router directory) throws TimeoutException, InterruptedException, OpenFailedException {
		final InternalCircuit circuit = circuitManager.getCleanInternalCircuit();
		try {
			final DirectoryCircuit dc = circuit.cannibalizeToDirectory(directory);
			return dc.openDirectoryStream(DIRECTORY_STREAM_TIMEOUT, true);
		} catch (StreamConnectFailedException e) {
			circuit.markForClose();
			throw new OpenFailedException("Failed to open directory stream");
		} catch (TorException e) {
			circuit.markForClose();
			throw new OpenFailedException("Failed to extend circuit to HSDir: "+ e.getMessage());
		}
	}

	private HSV3Descriptor parseDocument(Router dir, ByteBuffer body) {
		final byte[] bytes = new byte[body.remaining()];
		body.get(bytes);
		final HSV3DescriptorParser parser = new HSV3DescriptorParser(
				hiddenService.getBlindedPublicKey(),
				hiddenService.getSubcredential(),
				hiddenService.getClientAuthPrivateKey(),
				System.currentTimeMillis() / 1000,
				hiddenService.getTimePeriod().getPeriodNumber());
		try {
			final HSV3Descriptor descriptor = parser.parse(bytes);
			logger.debug("Parsed "+ descriptor + " for "+ hiddenService.getOnionAddressForLogging());
			return descriptor;
		} catch (TorParsingException e) {
			logger.info("Failed to parse v3 descriptor received from "+ dir + " for "+ hiddenService.getOnionAddressForLogging() + " : "+ e.getMessage());
			return null;
		}
	}
}
