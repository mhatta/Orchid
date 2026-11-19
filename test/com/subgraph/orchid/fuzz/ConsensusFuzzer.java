package com.subgraph.orchid.fuzz;

import java.nio.ByteBuffer;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.directory.DocumentParserFactoryImpl;

/** Fuzz target: the parser of consensus documents (network-status-version 3), as served by directory caches. */
public class ConsensusFuzzer {
	private static final DocumentParserFactoryImpl PARSERS = new DocumentParserFactoryImpl();

	public static void fuzzerTestOneInput(byte[] data) {
		FuzzSupport.quietLogging();
		final ByteBuffer buffer = ByteBuffer.wrap(data);
		try {
			PARSERS.createConsensusDocumentParser(buffer).parse();
		} catch (TorException e) {
			// refused: TorParsingException and the like
		}
	}
}
