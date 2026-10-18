package com.subgraph.orchid.circuits.path;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.fail;

import java.util.Collections;

import org.junit.Test;

import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorConfig;

/**
 * When no relay can be chosen (for example because no descriptors have
 * been downloaded yet), path selection must fail with
 * PathSelectionFailedException rather than a NullPointerException.
 */
public class CircuitPathChooserTest {

	private static CircuitPathChooser chooserWithNoRouters() {
		final Directory directory = createNiceMock(Directory.class);
		expect(directory.getAllRouters()).andStubReturn(Collections.<Router>emptyList());
		replay(directory);
		final TorConfig config = Tor.createConfig();
		return CircuitPathChooser.create(config, directory);
	}

	@Test
	public void testInternalPathWithNoRoutersFailsCleanly() throws Exception {
		try {
			chooserWithNoRouters().chooseInternalPath();
			fail("expected PathSelectionFailedException");
		} catch (PathSelectionFailedException e) {
			// expected
		}
	}

	@Test
	public void testPathWithNullFinalNodeFailsCleanly() throws Exception {
		try {
			chooserWithNoRouters().choosePathWithFinal(null);
			fail("expected PathSelectionFailedException");
		} catch (PathSelectionFailedException e) {
			// expected
		}
	}
}
