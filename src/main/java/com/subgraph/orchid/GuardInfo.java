package com.subgraph.orchid;

import java.util.Date;

/**
 * A snapshot of one entry guard of the sample that Orchid keeps (guard-spec,
 * proposal 271), for showing to users.  See {@link TorClient#getEntryGuards()}.
 *
 * @since 2.8.0
 */
public final class GuardInfo {
	/** Whether the guard could be reached the last time Orchid tried. */
	public enum Reachability {
		REACHABLE,
		UNREACHABLE,
		/** Not tried since Orchid started, or since the network changed. */
		UNKNOWN
	}

	private final RelayInfo relay;
	private final boolean primary;
	private final boolean confirmed;
	private final boolean listed;
	private final Reachability reachability;
	private final Date sampledOn;
	private final Date confirmedOn;

	/** For Orchid's own use; applications get these from {@link TorClient}. */
	public GuardInfo(RelayInfo relay, boolean primary, boolean confirmed, boolean listed,
			Reachability reachability, Date sampledOn, Date confirmedOn) {
		this.relay = relay;
		this.primary = primary;
		this.confirmed = confirmed;
		this.listed = listed;
		this.reachability = reachability;
		this.sampledOn = copy(sampledOn);
		this.confirmedOn = copy(confirmedOn);
	}

	private static Date copy(Date d) {
		return d == null ? null : new Date(d.getTime());
	}

	public RelayInfo getRelay() {
		return relay;
	}

	/** True if the guard is a primary guard, one of those circuits are built through first. */
	public boolean isPrimary() {
		return primary;
	}

	/** True if a circuit through the guard has been used, which makes it a guard Orchid keeps. */
	public boolean isConfirmed() {
		return confirmed;
	}

	/** True if the guard is listed in the current consensus as a guard. */
	public boolean isListed() {
		return listed;
	}

	public Reachability getReachability() {
		return reachability;
	}

	/** When the guard was added to the sample. */
	public Date getSampledOn() {
		return copy(sampledOn);
	}

	/** When the guard was confirmed, or null. */
	public Date getConfirmedOn() {
		return copy(confirmedOn);
	}

	@Override
	public String toString() {
		return relay + (primary ? " primary" : "") + (confirmed ? " confirmed" : "") + " " + reachability;
	}
}
