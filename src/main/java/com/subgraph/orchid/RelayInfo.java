package com.subgraph.orchid;

/**
 * A relay as shown to applications: in the path of a circuit
 * ({@link CircuitInfo#getPath()}) or as an entry guard ({@link GuardInfo}).
 * A snapshot: it does not change when the relay does.
 *
 * <p>The relays a client uses, and above all its entry guards, which it
 * keeps for months, are close to an identifier of the client: whoever
 * learns them can recognize it on another network.  Show them to the user,
 * but do not log them, send them anywhere (crash reports, analytics), put
 * them on the lock screen, or make them available to other apps through
 * an exported component.  {@link #toString()} leaves them out.
 *
 * @since 2.8.0
 */
public final class RelayInfo {
	private final String fingerprint;
	private final String nickname;
	private final String countryCode;

	/** For Orchid's own use; applications get these from {@link TorClient}. */
	public RelayInfo(String fingerprint, String nickname, String countryCode) {
		this.fingerprint = fingerprint;
		this.nickname = nickname;
		// "??" is how the GeoIP service says it does not know.
		this.countryCode = (countryCode == null || countryCode.equals("??")) ? null : countryCode;
	}

	/** The relay's RSA identity fingerprint, 40 upper-case hex digits. */
	public String getFingerprint() {
		return fingerprint;
	}

	/** The relay's nickname, or null if it is not known. */
	public String getNickname() {
		return nickname;
	}

	/**
	 * The two-letter country code of the relay's address in upper case
	 * ("DE"), or null if it is not known (the address is not in the GeoIP
	 * database, or the relay is not in the current consensus).
	 */
	public String getCountryCode() {
		return countryCode;
	}

	/**
	 * Only the country code: neither the fingerprint nor the nickname, so
	 * that logging the object does not record which relays were used.
	 */
	@Override
	public String toString() {
		return "relay {"+ (countryCode == null ? "??" : countryCode) +"}";
	}
}
