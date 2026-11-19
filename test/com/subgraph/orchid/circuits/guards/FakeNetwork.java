package com.subgraph.orchid.circuits.guards;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Descriptor;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

/**
 * An in-memory directory with relays for the guard tests: routers and
 * the directory are dynamic proxies that answer the few calls guard
 * selection makes.  Each relay is in its own /16 and family.
 */
public class FakeNetwork {

	/** A relay whose flags a test can change. */
	public static class Relay {
		public final HexDigest identity;
		public final String nickname;
		public final IPv4Address address;
		public boolean running = true;
		public boolean guard;
		public boolean hasDescriptor = true;
		public final Router router;

		Relay(int index, boolean guard) {
			final byte[] id = new byte[20];
			id[0] = (byte) (index >> 8);
			id[1] = (byte) index;
			id[19] = 1;
			this.identity = HexDigest.createFromDigestBytes(id);
			this.nickname = "relay"+ index;
			this.address = IPv4Address.createFromString((10 + index / 250) +"."+ (index % 250) +".0.1");
			this.guard = guard;
			this.router = (Router) Proxy.newProxyInstance(Router.class.getClassLoader(), new Class<?>[] { Router.class }, new InvocationHandler() {
				public Object invoke(Object proxy, Method m, Object[] args) {
					return answer(proxy, m, args);
				}
			});
		}

		private Object answer(Object proxy, Method m, Object[] args) {
			final String n = m.getName();
			if(n.equals("equals")) {
				return proxy == args[0];
			} else if(n.equals("hashCode")) {
				return System.identityHashCode(proxy);
			} else if(n.equals("toString")) {
				return nickname;
			} else if(n.equals("getIdentityHash")) {
				return identity;
			} else if(n.equals("getNickname")) {
				return nickname;
			} else if(n.equals("getAddress")) {
				return address;
			} else if(n.equals("isRunning")) {
				return running;
			} else if(n.equals("isPossibleGuard")) {
				return guard;
			} else if(n.equals("isValid") || n.equals("isFast") || n.equals("isStable") || n.equals("isDirectoryCache") || n.equals("hasBandwidth")) {
				return true;
			} else if(n.equals("getCurrentDescriptor")) {
				return hasDescriptor ? DESCRIPTOR : null;
			} else if(n.equals("getEstimatedBandwidth") || n.equals("getMeasuredBandwidth")) {
				return 1000;
			} else if(n.equals("getFamilyMembers") || n.equals("getFamilyIds")) {
				return Collections.emptySet();
			} else if(n.equals("getCountryCode")) {
				return "??";
			}
			return defaultValue(m.getReturnType());
		}
	}

	private static final Descriptor DESCRIPTOR = (Descriptor) Proxy.newProxyInstance(Descriptor.class.getClassLoader(),
			new Class<?>[] { Descriptor.class }, new InvocationHandler() {
				public Object invoke(Object proxy, Method m, Object[] args) {
					return defaultValue(m.getReturnType());
				}
			});

	public final List<Relay> relays = new ArrayList<Relay>();
	public final AtomicLong time = new AtomicLong(1800000000000L);
	public boolean haveConsensus = true;
	public List<Map<String, String>> guardState = new ArrayList<Map<String, String>>();
	public int stateWrites;
	/* Identities passed to Directory.requestDescriptorsNow(). */
	public final Set<HexDigest> descriptorsRequestedNow = new HashSet<HexDigest>();
	public final Directory directory;

	public FakeNetwork(int guards, int middles) {
		for(int i = 0; i < guards + middles; i++) {
			relays.add(new Relay(i, i < guards));
		}
		final ConsensusDocument consensus = (ConsensusDocument) Proxy.newProxyInstance(ConsensusDocument.class.getClassLoader(),
				new Class<?>[] { ConsensusDocument.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						final String n = m.getName();
						if(n.equals("getIntegerParameter")) {
							return args[1];
						} else if(n.equals("isLive")) {
							return true;
						} else if(n.equals("getWeightScaleParameter") || n.equals("getBandwidthWeight")) {
							return 10000;
						}
						return defaultValue(m.getReturnType());
					}
				});
		directory = (Directory) Proxy.newProxyInstance(Directory.class.getClassLoader(), new Class<?>[] { Directory.class }, new InvocationHandler() {
			@SuppressWarnings("unchecked")
			public Object invoke(Object proxy, Method m, Object[] args) {
				final String n = m.getName();
				if(n.equals("getAllRouters")) {
					final List<Router> all = new ArrayList<Router>();
					for(Relay r: relays) {
						all.add(r.router);
					}
					return all;
				} else if(n.equals("getRouterByIdentity")) {
					for(Relay r: relays) {
						if(r.identity.equals(args[0])) {
							return r.router;
						}
					}
					return null;
				} else if(n.equals("getCurrentConsensusDocument")) {
					return haveConsensus ? consensus : null;
				} else if(n.equals("getGuardState")) {
					final List<Map<String, String>> copy = new ArrayList<Map<String, String>>();
					for(Map<String, String> g: guardState) {
						copy.add(new LinkedHashMap<String, String>(g));
					}
					return copy;
				} else if(n.equals("requestDescriptorsNow")) {
					descriptorsRequestedNow.addAll((java.util.Collection<HexDigest>) args[0]);
					return null;
				} else if(n.equals("setGuardState")) {
					guardState = new ArrayList<Map<String, String>>((List<Map<String, String>>) args[0]);
					stateWrites++;
					return null;
				}
				return defaultValue(m.getReturnType());
			}
		});
	}

	public Relay relay(Router r) {
		for(Relay relay: relays) {
			if(relay.router == r) {
				return relay;
			}
		}
		return null;
	}

	public EntryGuards.Clock clock() {
		return new EntryGuards.Clock() {
			public long now() {
				return time.get();
			}
		};
	}

	public static Set<Router> none() {
		return new HashSet<Router>();
	}

	static Object defaultValue(Class<?> type) {
		if(type == boolean.class) {
			return false;
		} else if(type == int.class) {
			return 0;
		} else if(type == long.class) {
			return 0L;
		} else if(type == double.class) {
			return 0.0;
		} else if(List.class.isAssignableFrom(type)) {
			return new ArrayList<Object>();
		} else if(Set.class.isAssignableFrom(type)) {
			return new HashSet<Object>();
		}
		return null;
	}
}
