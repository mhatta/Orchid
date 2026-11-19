package com.subgraph.orchid.fuzz;

import java.nio.ByteBuffer;

import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.directory.DocumentParserFactoryImpl;

/** Fuzz target: the parser of directory authority key certificates. */
public class KeyCertificateFuzzer {
	private static final DocumentParserFactoryImpl PARSERS = new DocumentParserFactoryImpl();

	public static void fuzzerTestOneInput(byte[] data) {
		FuzzSupport.quietLogging();
		final ByteBuffer buffer = ByteBuffer.wrap(data);
		try {
			PARSERS.createKeyCertificateParser(buffer).parse();
		} catch (TorException e) {
			// refused: TorParsingException and the like
		}
	}
}
