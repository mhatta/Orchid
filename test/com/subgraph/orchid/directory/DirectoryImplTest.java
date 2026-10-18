package com.subgraph.orchid.directory;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;

import org.junit.Test;

import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.config.TorConfigImpl;

public class DirectoryImplTest {

	private static DirectoryImpl createDirectory(File dataDirectory) {
		final TorConfig config = new TorConfigImpl();
		config.setDataDirectory(dataDirectory);
		return new DirectoryImpl(config, null);
	}

	private static File emptyDataDirectory() throws Exception {
		final File f = File.createTempFile("orchid-test", "");
		f.delete();
		f.mkdirs();
		f.deleteOnExit();
		return f;
	}

	/*
	 * Starting with no cached consensus is normal (first start) and must not
	 * log a signature verification warning.
	 */
	@Test
	public void testEmptyCacheLoadsQuietly() throws Exception {
		final DirectoryImpl directory = createDirectory(emptyDataDirectory());
		final PrintStream saved = System.out;
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		System.setOut(new PrintStream(out, true));
		try {
			directory.loadFromStore();
		} finally {
			System.setOut(saved);
		}
		assertNull(directory.getCurrentConsensusDocument());
		assertFalse(directory.hasPendingConsensus());
		assertFalse("unexpected warning: "+ out, out.toString().contains("WARN"));
	}
}
