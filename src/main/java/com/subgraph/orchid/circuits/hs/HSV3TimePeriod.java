package com.subgraph.orchid.circuits.hs;

import com.subgraph.orchid.ConsensusDocument;

/**
 * Time period calculations for version 3 onion services
 * (rend-spec-v3 section 2.2.1 [TIME-PERIODS] and 2.2.2 [WHEN-HSDESC]).
 *
 * A time period is <code>hsdir_interval</code> minutes long (1440 by default)
 * and time periods are offset by a "rotation time offset" of 12 voting
 * periods (12 hours in the live network) so that a new period starts at
 * 12:00 UTC, half way between two shared random value (SRV) publications
 * which happen at 00:00 UTC.
 *
 * As required by the specification, the reference time is the valid-after
 * time of the latest consensus rather than the local clock.
 */
public final class HSV3TimePeriod {
	/** Default voting interval of the live network in seconds (one hour). */
	static final int DEFAULT_VOTING_INTERVAL_SECONDS = 3600;
	/** The SRV protocol run is 24 voting rounds (12 commit + 12 reveal). */
	static final int SRV_PROTOCOL_ROUNDS = 24;
	/** The rotation offset is the length of one SRV phase: 12 voting rounds. */
	static final int ROTATION_OFFSET_ROUNDS = 12;

	private final long periodLengthMinutes;
	private final long periodNumber;
	private final long referenceTimeSeconds;
	private final boolean betweenTpAndSrv;

	/**
	 * Compute the current time period from a consensus document.
	 */
	public static HSV3TimePeriod fromConsensus(ConsensusDocument consensus) {
		final long validAfter = consensus.getValidAfterTime().getTime() / 1000;
		long votingInterval = DEFAULT_VOTING_INTERVAL_SECONDS;
		if(consensus.getFreshUntilTime() != null) {
			final long fu = consensus.getFreshUntilTime().getTime() / 1000;
			if(fu > validAfter) {
				votingInterval = fu - validAfter;
			}
		}
		return new HSV3TimePeriod(validAfter, consensus.getHSDirIntervalParameter(), votingInterval);
	}

	/**
	 * @param referenceTimeSeconds The reference time (consensus valid-after) in seconds since the epoch.
	 * @param periodLengthMinutes The time period length in minutes (consensus parameter hsdir_interval).
	 * @param votingIntervalSeconds The consensus voting interval in seconds (3600 in the live network).
	 */
	public HSV3TimePeriod(long referenceTimeSeconds, long periodLengthMinutes, long votingIntervalSeconds) {
		this.referenceTimeSeconds = referenceTimeSeconds;
		this.periodLengthMinutes = periodLengthMinutes;
		final long rotationOffsetMinutes = (ROTATION_OFFSET_ROUNDS * votingIntervalSeconds) / 60;
		this.periodNumber = computePeriodNumber(referenceTimeSeconds, periodLengthMinutes, rotationOffsetMinutes);
		this.betweenTpAndSrv = computeBetweenTpAndSrv(referenceTimeSeconds, periodLengthMinutes, rotationOffsetMinutes, votingIntervalSeconds);
	}

	/**
	 * period_num = floor((minutes_since_epoch - rotation_offset) / period_length)
	 */
	static long computePeriodNumber(long timeSeconds, long periodLengthMinutes, long rotationOffsetMinutes) {
		final long minutes = timeSeconds / 60;
		return (minutes - rotationOffsetMinutes) / periodLengthMinutes;
	}

	/** Start time (seconds) of the time period with the given number. */
	static long startOfPeriod(long periodNumber, long periodLengthMinutes, long rotationOffsetMinutes) {
		return (periodNumber * periodLengthMinutes + rotationOffsetMinutes) * 60;
	}

	/**
	 * Mirrors hs_in_period_between_tp_and_srv() of the C implementation: return
	 * true if the reference time lies between the start of a time period (12:00)
	 * and the start of the next SRV protocol run (00:00); return false if it lies
	 * between the start of an SRV run (00:00) and the start of the next time
	 * period (12:00).
	 */
	static boolean computeBetweenTpAndSrv(long timeSeconds, long periodLengthMinutes, long rotationOffsetMinutes, long votingIntervalSeconds) {
		final long protocolRunLength = SRV_PROTOCOL_ROUNDS * votingIntervalSeconds;
		final long srvStartTime = (timeSeconds / protocolRunLength) * protocolRunLength;
		final long nextTp = computePeriodNumber(srvStartTime, periodLengthMinutes, rotationOffsetMinutes) + 1;
		final long tpStartTime = startOfPeriod(nextTp, periodLengthMinutes, rotationOffsetMinutes);
		if(timeSeconds >= srvStartTime && timeSeconds < tpStartTime) {
			return false;
		}
		return true;
	}

	public long getPeriodNumber() {
		return periodNumber;
	}

	public long getPeriodLengthMinutes() {
		return periodLengthMinutes;
	}

	public long getReferenceTimeSeconds() {
		return referenceTimeSeconds;
	}

	/**
	 * True if we are between a time period start and the next SRV publication.
	 * In that case a client fetching a descriptor uses the <em>current</em>
	 * SRV; otherwise it uses the <em>previous</em> SRV.
	 */
	public boolean isBetweenTpAndSrv() {
		return betweenTpAndSrv;
	}

	/**
	 * Select the shared random value a client must use to locate the HSDirs for
	 * the current time period, falling back to the disaster SRV when the
	 * consensus does not carry the needed value.
	 */
	public byte[] selectFetchSharedRandomValue(ConsensusDocument consensus) {
		final byte[] srv = betweenTpAndSrv ? consensus.getSharedRandomCurrentValue() : consensus.getSharedRandomPreviousValue();
		if(srv != null) {
			return srv;
		}
		return HSV3Crypto.disasterSharedRandomValue(periodLengthMinutes, periodNumber);
	}

	@Override
	public String toString() {
		return "TP#"+ periodNumber + " (" + periodLengthMinutes + " min)";
	}
}
