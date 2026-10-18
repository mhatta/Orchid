package com.subgraph.orchid.circuits.hs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.subgraph.orchid.crypto.Ed25519Certificate;
import com.subgraph.orchid.crypto.TorRandom;

/**
 * A decoded and decrypted version 3 onion service descriptor
 * (rend-spec-v3 section 2.4 [DESC-OUTER] and 2.5 [HS-DESC-ENC]).
 */
public final class HSV3Descriptor {
	private final long lifetimeMinutes;
	private final Ed25519Certificate signingKeyCert;
	private final long revisionCounter;
	private final boolean singleOnionService;
	private final boolean introAuthRequired;
	private final List<Integer> create2Formats;
	private final List<HSV3IntroductionPoint> introductionPoints;
	private final long receivedTimeSeconds;
	private final long timePeriodNumber;

	HSV3Descriptor(long lifetimeMinutes, Ed25519Certificate signingKeyCert, long revisionCounter, boolean singleOnionService,
			boolean introAuthRequired, List<Integer> create2Formats, List<HSV3IntroductionPoint> introductionPoints,
			long receivedTimeSeconds, long timePeriodNumber) {
		this.lifetimeMinutes = lifetimeMinutes;
		this.signingKeyCert = signingKeyCert;
		this.revisionCounter = revisionCounter;
		this.singleOnionService = singleOnionService;
		this.introAuthRequired = introAuthRequired;
		this.create2Formats = Collections.unmodifiableList(new ArrayList<Integer>(create2Formats));
		this.introductionPoints = Collections.unmodifiableList(new ArrayList<HSV3IntroductionPoint>(introductionPoints));
		this.receivedTimeSeconds = receivedTimeSeconds;
		this.timePeriodNumber = timePeriodNumber;
	}

	public long getLifetimeMinutes() {
		return lifetimeMinutes;
	}

	public Ed25519Certificate getSigningKeyCert() {
		return signingKeyCert;
	}

	/** The short term descriptor signing key (certified by the blinded key). */
	public byte[] getDescriptorSigningKey() {
		return signingKeyCert.getCertifiedKey();
	}

	public long getRevisionCounter() {
		return revisionCounter;
	}

	public boolean isSingleOnionService() {
		return singleOnionService;
	}

	/** True if the service requires client authentication at the introduction point ("intro-auth-required"). */
	public boolean isIntroAuthRequired() {
		return introAuthRequired;
	}

	public List<Integer> getCreate2Formats() {
		return create2Formats;
	}

	public List<HSV3IntroductionPoint> getIntroductionPoints() {
		return introductionPoints;
	}

	public List<HSV3IntroductionPoint> getShuffledIntroductionPoints() {
		final List<HSV3IntroductionPoint> list = new ArrayList<HSV3IntroductionPoint>(introductionPoints);
		final TorRandom r = new TorRandom();
		for(int i = list.size() - 1; i > 0; i--) {
			final int j = r.nextInt(i + 1);
			final HSV3IntroductionPoint tmp = list.get(i);
			list.set(i, list.get(j));
			list.set(j, tmp);
		}
		return list;
	}

	/** The time period number this descriptor was fetched for. */
	public long getTimePeriodNumber() {
		return timePeriodNumber;
	}

	/**
	 * A descriptor is considered usable for its advertised lifetime after it
	 * was received (the signing key certificate is checked at parse time).
	 */
	public boolean isExpired() {
		final long now = System.currentTimeMillis() / 1000;
		return now > receivedTimeSeconds + lifetimeMinutes * 60;
	}

	@Override
	public String toString() {
		return "HSV3Descriptor(revision="+ revisionCounter + ", lifetime="+ lifetimeMinutes + "min, intro points="+ introductionPoints.size() + ")";
	}
}
