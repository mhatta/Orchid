package com.subgraph.orchid.circuits.guards;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import org.junit.BeforeClass;
import org.junit.Test;

import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.IPv4Address;

/* L3: a bridge's descriptor must carry the identity key the bridge proved. */
public class BridgeDescriptorTest {
	private static TorPublicKey bridgeKey;
	private static TorPublicKey otherKey;

	@BeforeClass
	public static void keys() throws Exception {
		final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(1024);
		bridgeKey = new TorPublicKey((RSAPublicKey) g.generateKeyPair().getPublic());
		otherKey = new TorPublicKey((RSAPublicKey) g.generateKeyPair().getPublic());
	}

	private static RouterDescriptor descriptorWith(final TorPublicKey key) {
		return (RouterDescriptor) Proxy.newProxyInstance(RouterDescriptor.class.getClassLoader(),
				new Class<?>[] { RouterDescriptor.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						return m.getName().equals("getIdentityKey") ? key : null;
					}
				});
	}

	private static BridgeRouterImpl bridge() {
		return new BridgeRouterImpl(IPv4Address.createFromString("192.0.2.1"), 443);
	}

	@Test
	public void ownDescriptorIsAccepted() {
		final BridgeRouterImpl b = bridge();
		b.setIdentity(bridgeKey.getFingerprint());
		assertTrue(Bridges.isDescriptorOf(b, descriptorWith(bridgeKey)));
	}

	@Test
	public void descriptorOfAnotherRouterIsRefused() {
		final BridgeRouterImpl b = bridge();
		b.setIdentity(bridgeKey.getFingerprint());
		assertFalse(Bridges.isDescriptorOf(b, descriptorWith(otherKey)));
	}

	@Test
	public void unknownIdentityOrKeyIsRefused() {
		assertFalse(Bridges.isDescriptorOf(bridge(), descriptorWith(bridgeKey)));
		final BridgeRouterImpl b = bridge();
		b.setIdentity(bridgeKey.getFingerprint());
		assertFalse(Bridges.isDescriptorOf(b, descriptorWith(null)));
	}
}
