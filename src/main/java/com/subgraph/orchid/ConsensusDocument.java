package com.subgraph.orchid;

import java.util.List;
import java.util.Set;

import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.Timestamp;

public interface ConsensusDocument extends Document {
	enum ConsensusFlavor { NS, MICRODESC };
	enum SignatureStatus { STATUS_VERIFIED, STATUS_FAILED, STATUS_NEED_CERTS };
	
	interface RequiredCertificate {
		int getDownloadFailureCount();
		void incrementDownloadFailureCount();
		HexDigest getAuthorityIdentity();
		HexDigest getSigningKey();
	}
	
	ConsensusFlavor getFlavor();
	Timestamp getValidAfterTime();
	Timestamp getFreshUntilTime();
	Timestamp getValidUntilTime();
	int getConsensusMethod();
	int getVoteSeconds();
	int getDistSeconds();
	Set<String> getClientVersions();
	Set<String> getServerVersions();
	boolean isLive();
	List<RouterStatus> getRouterStatusEntries();
	
	SignatureStatus verifySignatures();
	Set<RequiredCertificate> getRequiredCertificates();
	
	HexDigest getSigningHash();
	HexDigest getSigningHash256();
	
	int getCircWindowParameter();
	int getWeightScaleParameter();
	
	int getBandwidthWeight(String tag);
	
	boolean getUseNTorHandshake();

	/**
	 * Return the value of an integer consensus parameter from the "params" line,
	 * clamped to [minValue, maxValue], or defaultValue if it is not present.
	 */
	int getIntegerParameter(String name, int defaultValue, int minValue, int maxValue);

	/** Length of a v3 onion service time period in minutes ("hsdir_interval", default 1440). */
	int getHSDirIntervalParameter();
	/** Number of v3 onion service descriptor replicas ("hsdir_n_replicas", default 2). */
	int getHSDirNReplicasParameter();
	/** Number of HSDirs a client may fetch a v3 descriptor from per replica ("hsdir_spread_fetch", default 3). */
	int getHSDirSpreadFetchParameter();

	/**
	 * Return the 32 byte shared random value from the "shared-rand-previous-value"
	 * line of the consensus, or null if the line is absent.
	 */
	byte[] getSharedRandomPreviousValue();
	/**
	 * Return the 32 byte shared random value from the "shared-rand-current-value"
	 * line of the consensus, or null if the line is absent.
	 */
	byte[] getSharedRandomCurrentValue();
}
