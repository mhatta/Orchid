package com.subgraph.orchid.circuits.path;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.easymock.IAnswer;
import org.easymock.EasyMock;
import org.junit.Test;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser.WeightRule;

/**
 * Bandwidth weights by position, as in Tor's compute_weighted_bandwidths().
 */
public class CircuitNodeChooserWeightParametersTest {
	private static final double DELTA = 0.001;

	private static ConsensusDocument consensus() {
		// distinct values so that a mixed-up tag is noticed
		final Map<String, Integer> w = new HashMap<String, Integer>();
		w.put("Wbd", 100); w.put("Wbe", 200); w.put("Wbg", 4142); w.put("Wbm", 10000);
		w.put("Wdb", 10000); w.put("Web", 10000); w.put("Wgb", 10000); w.put("Wmb", 10000);
		w.put("Wed", 9000); w.put("Wee", 8000); w.put("Weg", 7000); w.put("Wem", 6000);
		w.put("Wgd", 0); w.put("Wgg", 5858); w.put("Wgm", 5858);
		w.put("Wmd", 0); w.put("Wme", 0); w.put("Wmg", 4142); w.put("Wmm", 10000);
		final ConsensusDocument consensus = createNiceMock(ConsensusDocument.class);
		expect(consensus.getWeightScaleParameter()).andStubReturn(10000);
		expect(consensus.getBandwidthWeight(anyObject(String.class))).andStubAnswer(new IAnswer<Integer>() {
			public Integer answer() {
				final Integer v = w.get((String) EasyMock.getCurrentArguments()[0]);
				return (v == null) ? -1 : v;
			}
		});
		replay(consensus);
		return consensus;
	}

	private static Router router(boolean guard, boolean exit) {
		final Router r = createNiceMock(Router.class);
		expect(r.isPossibleGuard()).andStubReturn(guard);
		expect(r.isExit()).andStubReturn(exit);
		expect(r.isDirectoryCache()).andStubReturn(true);
		expect(r.getEstimatedBandwidth()).andStubReturn(1000); // 1,000,000 bytes
		replay(r);
		return r;
	}

	/* weight of a relay relative to its bandwidth */
	private static double weight(CircuitNodeChooserWeightParameters p, Router r) {
		return (p.calculateWeightedBandwidth(r) - 0.5) / 1000000.0;
	}

	@Test
	public void testDirectoryWeights() {
		final CircuitNodeChooserWeightParameters p = CircuitNodeChooserWeightParameters.create(consensus(), WeightRule.WEIGHT_FOR_DIR);
		assertEquals(0.4142, weight(p, router(true, false)), DELTA);  // Wbg
		assertEquals(1.0, weight(p, router(false, false)), DELTA);    // Wbm
		assertEquals(0.02, weight(p, router(false, true)), DELTA);    // Wbe
		assertEquals(0.01, weight(p, router(true, true)), DELTA);     // Wbd
	}

	@Test
	public void testExitWeights() {
		final CircuitNodeChooserWeightParameters p = CircuitNodeChooserWeightParameters.create(consensus(), WeightRule.WEIGHT_FOR_EXIT);
		assertEquals(0.7, weight(p, router(true, false)), DELTA);  // Weg
		assertEquals(0.6, weight(p, router(false, false)), DELTA); // Wem
		assertEquals(0.8, weight(p, router(false, true)), DELTA);  // Wee
		assertEquals(0.9, weight(p, router(true, true)), DELTA);   // Wed
	}

	@Test
	public void testGuardAndMiddleWeights() {
		final CircuitNodeChooserWeightParameters g = CircuitNodeChooserWeightParameters.create(consensus(), WeightRule.WEIGHT_FOR_GUARD);
		assertEquals(0.5858, weight(g, router(true, false)), DELTA); // Wgg
		assertEquals(0.0, weight(g, router(true, true)), DELTA);     // Wgd
		final CircuitNodeChooserWeightParameters m = CircuitNodeChooserWeightParameters.create(consensus(), WeightRule.WEIGHT_FOR_MID);
		assertEquals(0.4142, weight(m, router(true, false)), DELTA); // Wmg
		assertEquals(1.0, weight(m, router(false, false)), DELTA);   // Wmm
	}
}
