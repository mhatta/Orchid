package com.subgraph.orchid.fuzz;

import java.nio.ByteBuffer;

import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.directory.DocumentParserFactoryImpl;

/** Fuzz target: the parser of microdescriptors, as served by directory caches. */
public class MicrodescriptorFuzzer {
	private static final DocumentParserFactoryImpl PARSERS = new DocumentParserFactoryImpl();

	public static void fuzzerTestOneInput(byte[] data) {
		FuzzSupport.quietLogging();
		final ByteBuffer buffer = ByteBuffer.wrap(data);
		try {
			PARSERS.createRouterMicrodescriptorParser(buffer).parse();
		} catch (TorException e) {
			// refused: TorParsingException and the like
		}
	}
}
