package com.subgraph.orchid.circuits.hs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.subgraph.orchid.crypto.Ed25519Certificate;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

/**
 * An introduction point of a version 3 onion service, as listed in the
 * decrypted inner layer of the service descriptor (rend-spec-v3 section 2.5.2.2).
 */
public final class HSV3IntroductionPoint {
	private final List<LinkSpecifier> linkSpecifiers;
	private final byte[] onionKey;          /* "onion-key" ntor: the intro point relay's ntor onion key */
	private final Ed25519Certificate authKeyCert; /* "auth-key": certifies the intro point authentication key */
	private final byte[] encKey;            /* "enc-key" ntor: the service's curve25519 encryption key for this intro point (B) */
	private final Ed25519Certificate encKeyCert;  /* "enc-key-cert": cross-certification of enc-key */

	HSV3IntroductionPoint(List<LinkSpecifier> linkSpecifiers, byte[] onionKey, Ed25519Certificate authKeyCert, byte[] encKey, Ed25519Certificate encKeyCert) {
		this.linkSpecifiers = Collections.unmodifiableList(new ArrayList<LinkSpecifier>(linkSpecifiers));
		this.onionKey = onionKey;
		this.authKeyCert = authKeyCert;
		this.encKey = encKey;
		this.encKeyCert = encKeyCert;
	}

	public List<LinkSpecifier> getLinkSpecifiers() {
		return linkSpecifiers;
	}

	/** The relay's legacy RSA identity digest, from the link specifiers (may be null). */
	public HexDigest getLegacyIdentity() {
		final LinkSpecifier ls = LinkSpecifier.findByType(linkSpecifiers, LinkSpecifier.TYPE_LEGACY_ID);
		return ls == null ? null : ls.getLegacyIdentity();
	}

	/** The relay's Ed25519 identity, from the link specifiers (may be null). */
	public byte[] getEd25519Identity() {
		final LinkSpecifier ls = LinkSpecifier.findByType(linkSpecifiers, LinkSpecifier.TYPE_ED25519_ID);
		return (ls == null || ls.getData().length != 32) ? null : ls.getData();
	}

	public IPv4Address getIPv4Address() {
		final LinkSpecifier ls = LinkSpecifier.findByType(linkSpecifiers, LinkSpecifier.TYPE_IPV4);
		return ls == null ? null : ls.getIPv4Address();
	}

	public int getPort() {
		final LinkSpecifier ls = LinkSpecifier.findByType(linkSpecifiers, LinkSpecifier.TYPE_IPV4);
		return ls == null ? 0 : ls.getPort();
	}

	/** The ntor onion key of the introduction point relay. */
	public byte[] getOnionKey() {
		return onionKey.clone();
	}

	/** AUTH_KEY: the ed25519 introduction point authentication key (certified key of the auth-key cert). */
	public byte[] getAuthKey() {
		return authKeyCert.getCertifiedKey();
	}

	public Ed25519Certificate getAuthKeyCert() {
		return authKeyCert;
	}

	/** B: the curve25519 encryption key for this introduction point. */
	public byte[] getEncKey() {
		return encKey.clone();
	}

	public Ed25519Certificate getEncKeyCert() {
		return encKeyCert;
	}

	@Override
	public String toString() {
		return "IntroductionPoint("+ linkSpecifiers + ")";
	}
}
