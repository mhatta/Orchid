package com.subgraph.orchid.circuits;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;
import com.subgraph.orchid.circuits.hs.LinkSpecifier;
import com.subgraph.orchid.crypto.Curve25519;
import com.subgraph.orchid.crypto.TorKeyDerivation;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorRFC5869KeyDerivation;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

/**
 * The relay side of a circuit, for tests: a chain of simulated relays behind
 * one connection.  It answers CREATE2 / CREATE_FAST for the first hop and
 * RELAY_EXTEND2 for the following ones (ntor, server side), and keeps the
 * relay crypto state of every hop, so that tests can exchange relay cells
 * with a real {@link CircuitImpl} and check what it sends.
 *
 * Cells are processed on a thread of their own, like the cell reading
 * thread of a real connection.
 */
class FakeRelay implements Connection {
	private final static String PROTOID = "ntor-curve25519-sha256-1";
	private final static Charset CS = Charset.forName("ISO-8859-1");

	static class Hop {
		final String nickname;
		final byte[] identity;
		final byte[] ntorSecret;
		final byte[] ntorPublic;
		final byte[] ed25519Identity;
		final Router router;

		/*
		 * The relay's view of the hop: the client's key material with the
		 * forward and backward halves swapped, so that "forward" here is
		 * the direction towards the client.
		 */
		CircuitNodeCryptoState state;
		final List<RelayCell> received = new ArrayList<RelayCell>();
		List<Integer> extendLinkSpecifierTypes;

		Hop(String nickname, boolean hasNtorKey) {
			final TorRandom random = new TorRandom();
			this.nickname = nickname;
			this.identity = random.getBytes(20);
			this.ntorSecret = clamp(random.getBytes(32));
			this.ntorPublic = new byte[32];
			Curve25519.crypto_scalarmult_base(ntorPublic, ntorSecret);
			this.ed25519Identity = random.getBytes(32);

			final Router r = createNiceMock(Router.class);
			expect(r.getNickname()).andStubReturn(nickname);
			expect(r.getIdentityHash()).andStubReturn(HexDigest.createFromDigestBytes(identity));
			expect(r.getNTorOnionKey()).andStubReturn(hasNtorKey ? ntorPublic : null);
			expect(r.getEd25519Identity()).andStubReturn(ed25519Identity);
			expect(r.getAddress()).andStubReturn(new IPv4Address(0x7F000001));
			expect(r.getOnionPort()).andStubReturn(9001);
			replay(r);
			this.router = r;
		}
	}

	final List<Hop> hops = new ArrayList<Hop>();
	final List<Integer> controlCommands = new ArrayList<Integer>();
	private final BlockingQueue<Cell> queue = new LinkedBlockingQueue<Cell>();
	private final Thread thread;
	private volatile Circuit circuit;
	private volatile int circuitId;
	private volatile Throwable failure;

	/**
	 * @param hopCount The number of relays in the chain.
	 * @param withoutNtorKey The indexes of relays whose ntor onion key the
	 *        client does not know.
	 */
	FakeRelay(int hopCount, int... withoutNtorKey) {
		for(int i = 0; i < hopCount; i++) {
			boolean hasKey = true;
			for(int k: withoutNtorKey) {
				hasKey &= (k != i);
			}
			hops.add(new Hop("hop"+ i, hasKey));
		}
		thread = new Thread(new Runnable() {
			public void run() {
				processLoop();
			}
		});
		thread.setDaemon(true);
		thread.start();
	}

	Router router(int i) {
		return hops.get(i).router;
	}

	/** Any exception thrown while processing a cell, or null. */
	Throwable getFailure() {
		return failure;
	}

	/** Wait (up to 5 seconds) until every cell sent so far has been processed. */
	void drain() throws InterruptedException {
		for(int i = 0; i < 500 && pending.get() > 0; i++) {
			Thread.sleep(10);
		}
	}

	private final AtomicInteger pending = new AtomicInteger();

	private void processLoop() {
		while(true) {
			final Cell cell;
			try {
				cell = queue.take();
			} catch (InterruptedException e) {
				return;
			}
			try {
				processCell(cell);
			} catch(Throwable t) {
				if(failure == null) {
					failure = t;
				}
			} finally {
				pending.decrementAndGet();
			}
		}
	}

	private void processCell(Cell cell) {
		cell.resetToPayload();
		switch(cell.getCommand()) {
		case Cell.CREATE2:
			controlCommands.add(Cell.CREATE2);
			processCreate2(cell);
			break;
		case Cell.CREATE_FAST:
			controlCommands.add(Cell.CREATE_FAST);
			processCreateFast(cell);
			break;
		case Cell.RELAY:
		case Cell.RELAY_EARLY:
			processRelay(cell);
			break;
		default:
			controlCommands.add(cell.getCommand());
		}
	}

	private void processCreate2(Cell cell) {
		final Hop hop = hops.get(0);
		if(cell.getShort() != CircuitExtender.HANDSHAKE_TYPE_NTOR) {
			throw new IllegalStateException("Unexpected CREATE2 handshake type");
		}
		final byte[] onionskin = new byte[cell.getShort()];
		cell.getByteArray(onionskin);
		final byte[] km = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
		final byte[] reply = ntorServer(hop, onionskin, km);
		hop.state = relaySideState(km);
		final Cell created = CellImpl.createCell(circuitId, Cell.CREATED2);
		created.putShort(reply.length);
		created.putByteArray(reply);
		created.resetToPayload();	// as if just read from the connection
		circuit.deliverControlCell(created);
	}

	private void processCreateFast(Cell cell) {
		final byte[] x = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
		cell.getByteArray(x);
		final byte[] y = new TorRandom().getBytes(TorMessageDigest.TOR_DIGEST_SIZE);
		final byte[] km = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
		final byte[] kh = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
		new TorKeyDerivation(concat(x, y)).deriveKeys(km, kh);
		hops.get(0).state = relaySideState(km);
		final Cell created = CellImpl.createCell(circuitId, Cell.CREATED_FAST);
		created.putByteArray(y);
		created.putByteArray(kh);
		created.resetToPayload();	// as if just read from the connection
		circuit.deliverControlCell(created);
	}

	private void processRelay(Cell cell) {
		for(int i = 0; i < hops.size() && hops.get(i).state != null; i++) {
			if(hops.get(i).state.decryptBackwardCell(cell)) {
				processRelayAtHop(i, RelayCellImpl.createFromCell(null, asRelayCommand(cell)));
				return;
			}
		}
		throw new IllegalStateException("Relay cell not recognized by any hop");
	}

	/* RELAY_EARLY cells are relay cells too */
	private Cell asRelayCommand(Cell cell) {
		if(cell.getCommand() == Cell.RELAY) {
			return cell;
		}
		final Cell copy = CellImpl.createCell(cell.getCircuitId(), Cell.RELAY);
		copy.putByteArray(cell.getCellBytes(), Cell.CELL_HEADER_LEN, Cell.CELL_PAYLOAD_LEN);
		return copy;
	}

	/** Called for every relay cell that a hop recognizes. */
	protected void processRelayAtHop(int index, RelayCell cell) {
		final Hop hop = hops.get(index);
		hop.received.add(cell);
		if(cell.getRelayCommand() == RelayCell.RELAY_EXTEND2) {
			processExtend2(index, cell);
		}
	}

	private void processExtend2(int index, RelayCell cell) {
		final Hop next = hops.get(index + 1);
		final List<Integer> types = new ArrayList<Integer>();
		final int nspec = cell.getByte();
		for(int i = 0; i < nspec; i++) {
			final int type = cell.getByte();
			final byte[] data = new byte[cell.getByte()];
			cell.getByteArray(data);
			types.add(type);
			if(type == LinkSpecifier.TYPE_LEGACY_ID && !Arrays.equals(data, next.identity)) {
				throw new IllegalStateException("EXTEND2 names the wrong RSA identity");
			}
			if(type == LinkSpecifier.TYPE_ED25519_ID && !Arrays.equals(data, next.ed25519Identity)) {
				throw new IllegalStateException("EXTEND2 names the wrong Ed25519 identity");
			}
		}
		next.extendLinkSpecifierTypes = types;
		if(cell.getShort() != CircuitExtender.HANDSHAKE_TYPE_NTOR) {
			throw new IllegalStateException("Unexpected EXTEND2 handshake type");
		}
		final byte[] onionskin = new byte[cell.getShort()];
		cell.getByteArray(onionskin);
		final byte[] km = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
		final byte[] reply = ntorServer(next, onionskin, km);
		next.state = relaySideState(km);

		final ByteBuffer bb = ByteBuffer.allocate(2 + reply.length);
		bb.putShort((short) reply.length);
		bb.put(reply);
		sendBackward(index, RelayCell.RELAY_EXTENDED2, 0, bb.array());
	}

	/**
	 * Send a relay cell from hop <code>index</code> towards the client.
	 * Runs on the relay's thread or, before the circuit is used, on the
	 * test thread.
	 */
	synchronized void sendBackward(int index, int relayCommand, int streamId, byte[] data) {
		final RelayCellImpl cell = new RelayCellImpl(null, circuitId, streamId, relayCommand);
		cell.putByteArray(data);
		cell.setLength();
		final CircuitNodeCryptoState state = hops.get(index).state;
		state.updateForwardDigest(cell);
		cell.setDigest(state.getForwardDigestBytes());
		for(int i = index; i >= 0; i--) {
			hops.get(i).state.encryptForwardCell(cell);
		}
		circuit.deliverRelayCell(cell);
	}

	/* The ntor handshake, relay side (tor-spec section 5.1.4). */
	static byte[] ntorServer(Hop hop, byte[] onionskin, byte[] keyMaterialOut) {
		final ByteBuffer bb = ByteBuffer.wrap(onionskin);
		final byte[] id = new byte[20];
		final byte[] b = new byte[32];
		final byte[] x = new byte[32];
		bb.get(id);
		bb.get(b);
		bb.get(x);
		if(!Arrays.equals(id, hop.identity) || !Arrays.equals(b, hop.ntorPublic)) {
			throw new IllegalStateException("ntor onionskin is not addressed to "+ hop.nickname);
		}
		final byte[] ySecret = clamp(new TorRandom().getBytes(32));
		final byte[] y = new byte[32];
		Curve25519.crypto_scalarmult_base(y, ySecret);

		final byte[] secretInput = concat(exp(x, ySecret), exp(x, hop.ntorSecret), id, b, x, y, PROTOID.getBytes(CS));
		final byte[] keySeed = hmac(PROTOID + ":key_extract", secretInput);
		final byte[] verify = hmac(PROTOID + ":verify", secretInput);
		final byte[] authInput = concat(verify, id, b, y, x, PROTOID.getBytes(CS), "Server".getBytes(CS));
		final byte[] auth = hmac(PROTOID + ":mac", authInput);

		new TorRFC5869KeyDerivation(keySeed).deriveKeys(keyMaterialOut, new byte[TorMessageDigest.TOR_DIGEST_SIZE]);
		return concat(y, auth);
	}

	/* Df | Db | Kf | Kb as seen by the client becomes Db | Df | Kb | Kf */
	static CircuitNodeCryptoState relaySideState(byte[] km) {
		final int d = TorMessageDigest.TOR_DIGEST_SIZE;
		final int k = (km.length - 2 * d) / 2;
		final byte[] swapped = concat(
				Arrays.copyOfRange(km, d, 2 * d), Arrays.copyOfRange(km, 0, d),
				Arrays.copyOfRange(km, 2 * d + k, 2 * d + 2 * k), Arrays.copyOfRange(km, 2 * d, 2 * d + k));
		return CircuitNodeCryptoState.createFromKeyMaterial(swapped, null);
	}

	private static byte[] exp(byte[] point, byte[] scalar) {
		final byte[] out = new byte[32];
		Curve25519.crypto_scalarmult(out, scalar, point);
		return out;
	}

	private static byte[] clamp(byte[] key) {
		key[0] &= 248;
		key[31] &= 127;
		key[31] |= 64;
		return key;
	}

	private static byte[] hmac(String key, byte[] data) {
		try {
			final Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(key.getBytes(CS), "HmacSHA256"));
			return mac.doFinal(data);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	static byte[] concat(byte[]... parts) {
		int n = 0;
		for(byte[] p: parts) {
			n += p.length;
		}
		final ByteBuffer bb = ByteBuffer.allocate(n);
		for(byte[] p: parts) {
			bb.put(p);
		}
		return bb.array();
	}

	/* Connection */

	public Router getRouter() {
		return router(0);
	}

	public boolean isClosed() {
		return false;
	}

	public void sendCell(Cell cell) {
		pending.incrementAndGet();
		queue.add(cell);
	}

	public void removeCircuit(Circuit circuit) {
	}

	public int bindCircuit(Circuit circuit) {
		this.circuit = circuit;
		this.circuitId = 0x80000001;
		return circuitId;
	}
}
