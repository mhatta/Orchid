package com.subgraph.orchid.directory.downloader;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.data.HexDigest;

/*
 * M7: a missing descriptor that a circuit waits for is downloaded at once,
 * not when 16 are missing or ten minutes have passed.
 * L14: only the requested descriptors are fetched, and a descriptor that
 * stays missing is tried less and less often.
 */
public class DescriptorProcessorTest {
	private static final long SECOND = 1000;

	private final AtomicLong time = new AtomicLong(1800000000000L);
	private final List<Router> downloadable = new ArrayList<Router>();
	private final Set<HexDigest> requestedNow = new HashSet<HexDigest>();
	private DescriptorProcessor processor;

	private static HexDigest digest(int i, int tag) {
		final byte[] b = new byte[tag == 0 ? 20 : 32];
		b[0] = (byte) i;
		b[1] = (byte) tag;
		return HexDigest.createFromDigestBytes(b);
	}

	private static Router router(final int i) {
		return (Router) Proxy.newProxyInstance(Router.class.getClassLoader(), new Class<?>[] { Router.class }, new InvocationHandler() {
			public Object invoke(Object proxy, Method m, Object[] args) {
				if(m.getName().equals("getIdentityHash")) {
					return digest(i, 0);
				} else if(m.getName().equals("getMicrodescriptorDigest") || m.getName().equals("getDescriptorDigest")) {
					return digest(i, 1);
				} else if(m.getName().equals("hashCode")) {
					return i;
				} else if(m.getName().equals("equals")) {
					return proxy == args[0];
				}
				return null;
			}
		});
	}

	@Before
	public void setUp() {
		final ConsensusDocument consensus = (ConsensusDocument) Proxy.newProxyInstance(ConsensusDocument.class.getClassLoader(),
				new Class<?>[] { ConsensusDocument.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						return m.getName().equals("isLive") ? Boolean.TRUE : null;
					}
				});
		final Directory directory = (Directory) Proxy.newProxyInstance(Directory.class.getClassLoader(),
				new Class<?>[] { Directory.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						final String n = m.getName();
						if(n.equals("getCurrentConsensusDocument")) {
							return consensus;
						} else if(n.equals("getRoutersWithDownloadableDescriptors")) {
							return new ArrayList<Router>(downloadable);
						} else if(n.equals("getDescriptorsRequestedNow")) {
							return new HashSet<HexDigest>(requestedNow);
						}
						return null;
					}
				});
		processor = new DescriptorProcessor(new TorConfigImpl(), directory, new DescriptorProcessor.Clock() {
			public long now() {
				return time.get();
			}
		});
		for(int i = 0; i < 3; i++) {
			downloadable.add(router(i));
		}
	}

	private int requested() {
		int n = 0;
		for(List<HexDigest> part: processor.getDescriptorDigestsToDownload()) {
			n += part.size();
		}
		return n;
	}

	@Test
	public void fewMissingDescriptorsWaitTenMinutes() {
		assertEquals(3, requested());
		time.addAndGet(60 * SECOND);
		assertEquals(0, requested());
		time.addAndGet(10 * 60 * SECOND);
		assertEquals(3, requested());
	}

	@Test
	public void requestedDescriptorIsDownloadedAtOnce() {
		assertEquals(3, requested());
		time.addAndGet(5 * SECOND);
		requestedNow.add(digest(1, 0));
		// Only the requested descriptor, not every missing one.
		assertEquals(1, requested());
		// Tried again 15 seconds later while still missing.
		time.addAndGet(5 * SECOND);
		assertEquals(0, requested());
		time.addAndGet(11 * SECOND);
		assertEquals(1, requested());
	}

	@Test
	public void retriesBackOff() {
		assertEquals(3, requested());
		requestedNow.add(digest(1, 0));
		time.addAndGet(SECOND);
		assertEquals(1, requested());
		// 15, 30, 60, 120 and 240 seconds (ten minutes from the start the
		// ordinary download takes over).
		long wait = 15 * SECOND;
		for(int i = 0; i < 5; i++) {
			time.addAndGet(wait - SECOND);
			assertEquals("try " + i + " too early", 0, requested());
			time.addAndGet(SECOND);
			assertEquals("try " + i, 1, requested());
			wait *= 2;
		}
	}

	@Test
	public void newRequestIsDownloadedDespiteBackoff() {
		assertEquals(3, requested());
		requestedNow.add(digest(1, 0));
		time.addAndGet(SECOND);
		assertEquals(1, requested());
		time.addAndGet(15 * SECOND);
		assertEquals(1, requested());
		// Now waiting 30 seconds for router 1; a request for router 2 goes at once.
		time.addAndGet(SECOND);
		requestedNow.add(digest(2, 0));
		assertEquals(2, requested());
		// And the wait starts again at 15 seconds.
		time.addAndGet(15 * SECOND);
		assertEquals(2, requested());
	}

	@Test
	public void backoffResetsWhenRequestIsSatisfied() {
		assertEquals(3, requested());
		requestedNow.add(digest(1, 0));
		time.addAndGet(SECOND);
		assertEquals(1, requested());
		time.addAndGet(15 * SECOND);
		assertEquals(1, requested());
		// Router 1's descriptor arrives.
		requestedNow.clear();
		downloadable.remove(1);
		time.addAndGet(SECOND);
		assertEquals(0, requested());
		// Later it is missing and wanted again: fetched at once, retried after 15 seconds.
		downloadable.add(router(1));
		requestedNow.add(digest(1, 0));
		time.addAndGet(SECOND);
		assertEquals(1, requested());
		time.addAndGet(15 * SECOND);
		assertEquals(1, requested());
	}

	@Test
	public void requestForAnotherRouterChangesNothing() {
		assertEquals(3, requested());
		time.addAndGet(5 * SECOND);
		requestedNow.add(digest(9, 0));
		assertEquals(0, requested());
	}
}
