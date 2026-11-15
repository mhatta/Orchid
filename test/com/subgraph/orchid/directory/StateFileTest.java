package com.subgraph.orchid.directory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.DirectoryStore;

public class StateFileTest {
	private static final String ID1 = "0123456789ABCDEF0123456789ABCDEF01234567";
	private static final String ID2 = "89ABCDEF0123456789ABCDEF0123456789ABCDEF";

	private String written;
	private StateFile stateFile;

	@Before
	public void setUp() {
		final DirectoryStore store = (DirectoryStore) Proxy.newProxyInstance(DirectoryStore.class.getClassLoader(),
				new Class<?>[] { DirectoryStore.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						if(m.getName().equals("writeData")) {
							final ByteBuffer b = ((ByteBuffer) args[1]).duplicate();
							final byte[] bytes = new byte[b.remaining()];
							b.get(bytes);
							written = new String(bytes, StandardCharsets.ISO_8859_1);
						}
						return null;
					}
				});
		stateFile = new StateFile(store);
	}

	private void parse(String s) {
		stateFile.parseBuffer(ByteBuffer.wrap(s.getBytes(StandardCharsets.ISO_8859_1)));
	}

	@Test
	public void legacyGuardsAreMigrated() throws Exception {
		parse("TorVersion Orchid 2.5.2\n"
				+ "EntryGuard first "+ ID1 +"\n"
				+ "EntryGuardAddedBy "+ ID1 +" Orchid-2.5.2 2026-10-01 12:00:00\n"
				+ "EntryGuardDownSince 2026-11-01 00:00:00 2026-11-01 01:00:00\n"
				+ "EntryGuard second "+ ID2 +"\n"
				+ "EntryGuardAddedBy "+ ID2 +" Orchid-2.5.2 2026-10-02 12:00:00\n"
				+ "EntryGuardUnlistedSince 2026-11-03 00:00:00\n"
				+ "EntryGuard broken "+ ID2 +"\n");
		final List<Map<String, String>> guards = stateFile.getGuards();
		assertEquals(2, guards.size());

		final Map<String, String> a = guards.get(0);
		assertEquals("default", a.get("in"));
		assertEquals(ID1, a.get("rsa_id"));
		assertEquals("first", a.get("nickname"));
		assertEquals("Orchid-2.5.2", a.get("sampled_by"));
		assertEquals("1", a.get("listed"));
		assertEquals("0", a.get("confirmed_idx"));
		final Date sampled = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2026-10-01 12:00:00");
		assertEquals(sampled, StateFile.parseDate(a.get("sampled_on")));
		final Date confirmed = StateFile.parseDate(a.get("confirmed_on"));
		assertNotNull(confirmed);
		assertTrue(Math.abs(confirmed.getTime() - System.currentTimeMillis()) < 60 * 1000L);

		final Map<String, String> b = guards.get(1);
		assertEquals("0", b.get("listed"));
		assertNotNull(StateFile.parseDate(b.get("unlisted_since")));
		assertEquals("1", b.get("confirmed_idx"));

		stateFile.setGuards(guards);
		assertTrue(written.startsWith("TorVersion Orchid 2.5.2\n"));
		assertTrue(written.contains("Guard in=default rsa_id="+ ID1 +" nickname=first "));
		assertTrue(!written.contains("EntryGuard"));
	}

	@Test
	public void newFormatRoundTrip() {
		final String line = "Guard in=default rsa_id="+ ID1 +" nickname=x sampled_on=2026-10-01T12:00:00"
				+ " sampled_by=Orchid-2.6.0 listed=1 pb_use_attempts=3.0 confirmed_idx=0 confirmed_on=2026-10-05T00:00:00";
		parse("# comment\n"+ line +"\nGuard in=default nickname=noid sampled_on=2026-10-01T12:00:00\n");
		final List<Map<String, String>> guards = stateFile.getGuards();
		assertEquals(1, guards.size());
		assertEquals("3.0", guards.get(0).get("pb_use_attempts"));
		stateFile.setGuards(guards);
		assertEquals("# comment\n"+ line +"\n", written);
	}

	@Test
	public void newFormatWinsOverLegacy() {
		parse("EntryGuard old "+ ID2 +"\n"
				+ "EntryGuardAddedBy "+ ID2 +" Orchid-2.5.2 2026-10-02 12:00:00\n"
				+ "Guard in=default rsa_id="+ ID1 +" sampled_on=2026-10-01T12:00:00\n");
		final List<Map<String, String>> guards = stateFile.getGuards();
		assertEquals(1, guards.size());
		assertEquals(ID1, guards.get(0).get("rsa_id"));
	}

	@Test
	public void setGuardsWritesInOrder() {
		final List<Map<String, String>> guards = new ArrayList<Map<String, String>>();
		for(String id: new String[] { ID2, ID1 }) {
			final Map<String, String> g = new LinkedHashMap<String, String>();
			g.put("in", "default");
			g.put("rsa_id", id);
			g.put("sampled_on", StateFile.formatDate(new Date(0)));
			guards.add(g);
		}
		stateFile.setGuards(guards);
		assertEquals("Guard in=default rsa_id="+ ID2 +" sampled_on=1970-01-01T00:00:00\n"
				+ "Guard in=default rsa_id="+ ID1 +" sampled_on=1970-01-01T00:00:00\n", written);
	}

	@Test
	public void dates() {
		assertEquals("1970-01-01T00:00:00", StateFile.formatDate(new Date(0)));
		assertEquals(new Date(1000), StateFile.parseDate("1970-01-01T00:00:01"));
		assertNull(StateFile.parseDate("1970-01-01 00:00:01"));
		assertNull(StateFile.parseDate(null));
	}
}
