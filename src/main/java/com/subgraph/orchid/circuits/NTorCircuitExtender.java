package com.subgraph.orchid.circuits;

import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.hs.LinkSpecifier;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorNTorKeyAgreement;
import com.subgraph.orchid.logging.Logger;

public class NTorCircuitExtender {
    private static final Logger logger = Logger.getInstance(NTorCircuitExtender.class);
	
    private final CircuitExtender extender;
    private final Router router;
    private final TorNTorKeyAgreement kex;

    public NTorCircuitExtender(CircuitExtender extender, Router router) {
        this.extender = extender;
        this.router = router;
        this.kex = new TorNTorKeyAgreement(router.getIdentityHash(), router.getNTorOnionKey());
    }

    CircuitNode extendTo() {
        final byte[] onion = kex.createOnionSkin();
        logger.debug("Extending circuit to "+ router.getNickname() + " with ntor inside RELAY_EXTEND2");
        final RelayCell cell = createExtend2Cell(onion);
        extender.sendRelayCell(cell);
        final RelayCell response = extender.receiveRelayResponse(RelayCell.RELAY_EXTENDED2, router);
        return processExtended2(response);
    }

    /*
     * EXTEND2 (tor-spec section 5.1.2): the link specifiers name the target
     * by its IPv4 address and ORPort, its RSA identity and, when it is
     * known, its Ed25519 identity, which the extending relay then checks.
     */
    RelayCell createExtend2Cell(byte[] ntorOnionskin) {
        final RelayCell cell = extender.createRelayCell(RelayCell.RELAY_EXTEND2);
        final byte[] ed25519Identity = router.getEd25519Identity();

        cell.putByte((ed25519Identity != null) ? 3 : 2);

        cell.putByte(LinkSpecifier.TYPE_IPV4);
        cell.putByte(6);
        cell.putByteArray(router.getAddress().getAddressDataBytes());
        cell.putShort(router.getOnionPort());

        cell.putByte(LinkSpecifier.TYPE_LEGACY_ID);
        cell.putByte(20);
        cell.putByteArray(router.getIdentityHash().getRawBytes());

        if(ed25519Identity != null) {
            cell.putByte(LinkSpecifier.TYPE_ED25519_ID);
            cell.putByte(ed25519Identity.length);
            cell.putByteArray(ed25519Identity);
        }

        cell.putShort(CircuitExtender.HANDSHAKE_TYPE_NTOR);
        cell.putShort(ntorOnionskin.length);
        cell.putByteArray(ntorOnionskin);
        return cell;
    }

    private CircuitNode processExtended2(RelayCell cell) {
        final int payloadLength = cell.getShort();
        if(payloadLength > cell.cellBytesRemaining()) {
            throw new TorException("Incorrect payload length value in RELAY_EXTENED2 cell");
        }
        byte[] payload = new byte[payloadLength];
        cell.getByteArray(payload);

        return processPayload(payload);
    }

    private CircuitNode processPayload(byte[] payload) {
        final byte[] keyMaterial = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
        final byte[] verifyDigest = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
        if(!kex.deriveKeysFromHandshakeResponse(payload, keyMaterial, verifyDigest)) {
            throw new TorException("Handshake with "+ router.getNickname() + " failed: bad authentication in RELAY_EXTENDED2");
        }
        return extender.createNewNode(router, keyMaterial, verifyDigest);
    }
}
