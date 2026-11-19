package com.subgraph.orchid.fuzz;

import java.nio.ByteBuffer;

import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.directory.DocumentParserFactoryImpl;

/** Fuzz target: the parser of router descriptors with signature checking, as a bridge serves its own. */
public class RouterDescriptorFuzzer {
	private static final DocumentParserFactoryImpl PARSERS = new DocumentParserFactoryImpl();

	public static void fuzzerTestOneInput(byte[] data) {
		FuzzSupport.quietLogging();
		final ByteBuffer buffer = ByteBuffer.wrap(data);
		try {
			PARSERS.createRouterDescriptorParser(buffer, true).parse();
		} catch (TorException e) {
			// refused: TorParsingException and the like
		}
	}
}
