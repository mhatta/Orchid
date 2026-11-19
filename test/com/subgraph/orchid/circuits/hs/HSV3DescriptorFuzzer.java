package com.subgraph.orchid.circuits.hs;

import java.util.Arrays;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.fuzz.FuzzSupport;

/**
 * Fuzz target: v3 onion service descriptors.  The first byte of the input
 * chooses what the rest is:
 *
 * <ul>
 * <li>0: a whole descriptor, as an HSDir serves it.  The keys are fixed,
 * so the fuzzer mostly reaches the outer layer and its signature check;
 * that is what an HSDir can send.</li>
 * <li>1: 32 bytes of subcredential, 32 bytes of client authorization key,
 * then the plaintext of the superencrypted layer (desc-auth-type ...).</li>
 * <li>2: 32 bytes of descriptor signing key, then the plaintext of the
 * encrypted layer (create2-formats, introduction-point ...).  The key is
 * part of the input so that the introduction point certificates of a seed
 * verify and the fuzzer gets past them.</li>
 * </ul>
 *
 * Layers 1 and 2 are only readable to whoever knows the onion address, so
 * there the attacker is the service itself.
 */
public class HSV3DescriptorFuzzer {
	private static final long NOW = 1800000000L;
	private static final long PERIOD = 20000;
	private static final byte[] BLINDED = filled(0x11);
	private static final byte[] SUBCREDENTIAL = filled(0x22);

	private static byte[] filled(int b) {
		final byte[] k = new byte[32];
		Arrays.fill(k, (byte) b);
		return k;
	}

	public static void fuzzerTestOneInput(byte[] data) {
		FuzzSupport.quietLogging();
		if(data.length < 1) {
			return;
		}
		try {
			switch((data[0] & 0xff) % 3) {
			case 0:
				new HSV3DescriptorParser(BLINDED, SUBCREDENTIAL, null, NOW, PERIOD)
						.parse(Arrays.copyOfRange(data, 1, data.length));
				break;
			case 1:
				if(data.length < 65) {
					return;
				}
				new HSV3DescriptorParser(BLINDED, Arrays.copyOfRange(data, 1, 33), Arrays.copyOfRange(data, 33, 65), NOW, PERIOD)
						.parseFirstLayerAndGetCookie(Arrays.copyOfRange(data, 65, data.length));
				break;
			default:
				if(data.length < 33) {
					return;
				}
				new HSV3DescriptorParser(BLINDED, SUBCREDENTIAL, null, NOW, PERIOD)
						.parseInnerLayer(Arrays.copyOfRange(data, 33, data.length), 180, null, 1, Arrays.copyOfRange(data, 1, 33));
				break;
			}
		} catch (TorException e) {
			// refused: TorParsingException
		}
	}
}
