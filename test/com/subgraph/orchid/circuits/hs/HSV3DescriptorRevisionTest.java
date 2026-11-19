package com.subgraph.orchid.circuits.hs;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.crypto.Ed25519Certificate;

/*
 * M3: an HSDir cannot roll a service back to an older descriptor (with
 * introduction points the service no longer uses) once a newer one of the
 * same time period has been accepted.
 */
public class HSV3DescriptorRevisionTest {
	private static final long PERIOD = 20000;

	private HiddenService hs;

	private static HSV3Descriptor descriptor(long revision, long period) {
		return new HSV3Descriptor(180, (Ed25519Certificate) null, revision, false, false,
				Collections.<Integer>singletonList(2), Collections.<HSV3IntroductionPoint>emptyList(),
				System.currentTimeMillis() / 1000, period);
	}

	@Before
	public void setUp() {
		final byte[] key = new byte[32];
		key[0] = 0x58;
		for(int i = 1; i < 32; i++) {
			key[i] = 0x66;
		}
		hs = new HiddenService(new TorConfigImpl(), HSV3Address.parse(HSV3Address.encode(key) + ".onion"));
	}

	@Test
	public void olderRevisionIsRefused() {
		final HSV3Descriptor newer = descriptor(1000, PERIOD);
		hs.setDescriptor(newer);
		final HSV3Descriptor older = descriptor(999, PERIOD);
		assertFalse(hs.isRevisionAcceptable(older));
		hs.setDescriptor(older);
		assertSame(newer, hs.getDescriptor());
	}

	@Test
	public void sameAndNewerRevisionsAreAccepted() {
		hs.setDescriptor(descriptor(1000, PERIOD));
		final HSV3Descriptor again = descriptor(1000, PERIOD);
		assertTrue(hs.isRevisionAcceptable(again));
		hs.setDescriptor(again);
		assertSame(again, hs.getDescriptor());
		final HSV3Descriptor newer = descriptor(1500, PERIOD);
		hs.setDescriptor(newer);
		assertSame(newer, hs.getDescriptor());
	}

	/* The counter starts again with each time period's blinded key. */
	@Test
	public void revisionsAreKeptPerTimePeriod() {
		hs.setDescriptor(descriptor(1000, PERIOD));
		assertTrue(hs.isRevisionAcceptable(descriptor(5, PERIOD + 1)));
		hs.setDescriptor(descriptor(5, PERIOD + 1));
		assertFalse(hs.isRevisionAcceptable(descriptor(999, PERIOD)));
		assertFalse(hs.isRevisionAcceptable(descriptor(4, PERIOD + 1)));
	}

	/* What was accepted is remembered after the descriptor is dropped (a new time period). */
	@Test
	public void revisionIsRememberedWithoutDescriptor() {
		hs.setDescriptor(descriptor(1000, PERIOD));
		hs.setDescriptor(null);
		assertFalse(hs.isRevisionAcceptable(descriptor(999, PERIOD)));
	}
}
