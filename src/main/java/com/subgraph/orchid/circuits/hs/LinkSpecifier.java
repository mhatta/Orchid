package com.subgraph.orchid.circuits.hs;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

/**
 * A link specifier as used in EXTEND2 cells, v3 descriptors and INTRODUCE1
 * cells (tor-spec section 5.1.2 "EXTEND and EXTENDED cells"):
 * <pre>
 *   LSTYPE [1 byte]
 *   LSLEN  [1 byte]
 *   LSPEC  [LSLEN bytes]
 * </pre>
 * Types: 0 = TLS-over-TCP IPv4 (4 byte address + 2 byte port),
 * 1 = TLS-over-TCP IPv6 (16 + 2), 2 = legacy (RSA SHA1) identity (20),
 * 3 = Ed25519 identity (32).  Unknown types are preserved verbatim.
 */
public final class LinkSpecifier {
	public static final int TYPE_IPV4 = 0;
	public static final int TYPE_IPV6 = 1;
	public static final int TYPE_LEGACY_ID = 2;
	public static final int TYPE_ED25519_ID = 3;

	private final int type;
	private final byte[] data;

	public LinkSpecifier(int type, byte[] data) {
		if(data.length > 255) {
			throw new IllegalArgumentException("Link specifier too long");
		}
		this.type = type;
		this.data = data.clone();
	}

	public static LinkSpecifier ipv4(IPv4Address address, int port) {
		final ByteBuffer bb = ByteBuffer.allocate(6);
		bb.put(address.getAddressDataBytes());
		bb.putShort((short) port);
		return new LinkSpecifier(TYPE_IPV4, bb.array());
	}

	public static LinkSpecifier legacyId(HexDigest identity) {
		return new LinkSpecifier(TYPE_LEGACY_ID, identity.getRawBytes());
	}

	public static LinkSpecifier ed25519Id(byte[] identity) {
		return new LinkSpecifier(TYPE_ED25519_ID, identity);
	}

	/**
	 * Build the link specifiers describing a router, as sent to an onion
	 * service to identify the rendezvous point: IPv4, legacy id and (when known)
	 * ed25519 id.
	 */
	public static List<LinkSpecifier> forRouter(Router router) {
		final List<LinkSpecifier> specs = new ArrayList<LinkSpecifier>(3);
		specs.add(ipv4(router.getAddress(), router.getOnionPort()));
		specs.add(legacyId(router.getIdentityHash()));
		final byte[] ed = router.getEd25519Identity();
		if(ed != null && ed.length == 32) {
			specs.add(ed25519Id(ed));
		}
		return specs;
	}

	/**
	 * Parse a list of link specifiers prefixed by the one byte count NSPEC.
	 */
	public static List<LinkSpecifier> parseList(byte[] encoded) {
		return parseList(ByteBuffer.wrap(encoded));
	}

	public static List<LinkSpecifier> parseList(ByteBuffer bb) {
		if(bb.remaining() < 1) {
			throw new TorParsingException("Missing link specifier count");
		}
		final int n = bb.get() & 0xFF;
		final List<LinkSpecifier> specs = new ArrayList<LinkSpecifier>(n);
		for(int i = 0; i < n; i++) {
			if(bb.remaining() < 2) {
				throw new TorParsingException("Truncated link specifier");
			}
			final int type = bb.get() & 0xFF;
			final int len = bb.get() & 0xFF;
			if(bb.remaining() < len) {
				throw new TorParsingException("Truncated link specifier data");
			}
			final byte[] data = new byte[len];
			bb.get(data);
			specs.add(new LinkSpecifier(type, data));
		}
		return specs;
	}

	/**
	 * Encode a list of link specifiers prefixed by the one byte count NSPEC.
	 */
	public static byte[] encodeList(List<LinkSpecifier> specs) {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(specs.size());
		for(LinkSpecifier ls: specs) {
			out.write(ls.type);
			out.write(ls.data.length);
			out.write(ls.data, 0, ls.data.length);
		}
		return out.toByteArray();
	}

	public static LinkSpecifier findByType(List<LinkSpecifier> specs, int type) {
		for(LinkSpecifier ls: specs) {
			if(ls.type == type) {
				return ls;
			}
		}
		return null;
	}

	public int getType() {
		return type;
	}

	public byte[] getData() {
		return data.clone();
	}

	/** For a legacy id specifier: the 20 byte RSA identity digest. */
	public HexDigest getLegacyIdentity() {
		if(type != TYPE_LEGACY_ID || data.length != 20) {
			return null;
		}
		return HexDigest.createFromDigestBytes(data);
	}

	/** For an IPv4 specifier: the address. */
	public IPv4Address getIPv4Address() {
		if(type != TYPE_IPV4 || data.length != 6) {
			return null;
		}
		int addr = 0;
		for(int i = 0; i < 4; i++) {
			addr = (addr << 8) | (data[i] & 0xFF);
		}
		return new IPv4Address(addr);
	}

	/** For an IPv4 or IPv6 specifier: the port. */
	public int getPort() {
		if((type == TYPE_IPV4 && data.length == 6) || (type == TYPE_IPV6 && data.length == 18)) {
			return ((data[data.length - 2] & 0xFF) << 8) | (data[data.length - 1] & 0xFF);
		}
		return 0;
	}

	@Override
	public boolean equals(Object o) {
		if(!(o instanceof LinkSpecifier)) {
			return false;
		}
		final LinkSpecifier other = (LinkSpecifier) o;
		return other.type == type && Arrays.equals(other.data, data);
	}

	@Override
	public int hashCode() {
		return 31 * type + Arrays.hashCode(data);
	}

	@Override
	public String toString() {
		switch(type) {
		case TYPE_IPV4:
			return "ipv4:"+ getIPv4Address() + ":" + getPort();
		case TYPE_LEGACY_ID:
			return "legacy-id:"+ getLegacyIdentity();
		case TYPE_ED25519_ID:
			return "ed25519-id:"+ data.length + " bytes";
		default:
			return "ls-type-"+ type + ":" + data.length + " bytes";
		}
	}
}
