package com.subgraph.orchid.circuits;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;
import com.subgraph.orchid.crypto.TorCreateFastKeyAgreement;
import com.subgraph.orchid.crypto.TorKeyAgreement;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorNTorKeyAgreement;
import com.subgraph.orchid.logging.Logger;

/**
 * Builds a circuit hop by hop.
 *
 * Every hop is created with the ntor handshake: the first one with a CREATE2
 * cell, the others with RELAY_EXTEND2.  The TAP handshake (CREATE, EXTEND) is
 * no longer accepted by relays (proposal 350) and is not implemented.  The
 * only exception is a first hop whose ntor onion key is not known yet, such
 * as a fallback directory or a bridge contacted before its descriptor is
 * available; that hop is created with CREATE_FAST, as Tor does.
 */
public class CircuitExtender {
    private static final Logger logger = Logger.getInstance(CircuitExtender.class);

    /** The handshake type of ntor in CREATE2 and EXTEND2 cells. */
    final static int HANDSHAKE_TYPE_NTOR = 0x0002;

    private final CircuitImpl circuit;

    CircuitExtender(CircuitImpl circuit) {
        this.circuit = circuit;
    }

    /**
     * Create the first hop of the circuit, over the connection the circuit
     * is bound to.
     */
    CircuitNode createFirstHop(Router targetRouter) {
        if(targetRouter.getNTorOnionKey() != null) {
            return createNtorTo(targetRouter);
        } else {
            logger.debug("No ntor onion key known for "+ targetRouter + ", creating the first hop with CREATE_FAST");
            return createFastTo(targetRouter);
        }
    }

    private CircuitNode createNtorTo(Router targetRouter) {
        logger.debug("Creating first hop to "+ targetRouter + " with CREATE2 (ntor)");
        final TorNTorKeyAgreement kex = new TorNTorKeyAgreement(targetRouter.getIdentityHash(), targetRouter.getNTorOnionKey());
        final byte[] onionskin = kex.createOnionSkin();
        final Cell cell = CellImpl.createCell(circuit.getCircuitId(), Cell.CREATE2);
        cell.putShort(HANDSHAKE_TYPE_NTOR);
        cell.putShort(onionskin.length);
        cell.putByteArray(onionskin);
        circuit.sendCell(cell);

        final Cell response = receiveCreateResponse(Cell.CREATED2, targetRouter);
        final int length = response.getShort();
        if(length > response.cellBytesRemaining()) {
            throw new TorException("Incorrect handshake length in CREATED2 cell from "+ targetRouter);
        }
        final byte[] reply = new byte[length];
        response.getByteArray(reply);
        return appendFirstHop(targetRouter, kex, reply);
    }

    private CircuitNode createFastTo(Router targetRouter) {
        final TorCreateFastKeyAgreement kex = new TorCreateFastKeyAgreement();
        final Cell cell = CellImpl.createCell(circuit.getCircuitId(), Cell.CREATE_FAST);
        cell.putByteArray(kex.createOnionSkin());
        circuit.sendCell(cell);

        final Cell response = receiveCreateResponse(Cell.CREATED_FAST, targetRouter);
        final byte[] reply = new byte[TorMessageDigest.TOR_DIGEST_SIZE * 2];
        response.getByteArray(reply);
        return appendFirstHop(targetRouter, kex, reply);
    }

    private Cell receiveCreateResponse(int expectedCommand, Router targetRouter) {
        final String expected = (expectedCommand == Cell.CREATED2) ? "CREATED2" : "CREATED_FAST";
        final Cell cell = circuit.receiveControlCellResponse();
        if(cell == null) {
            throw noResponseException("waiting for "+ expected + " response from "+ targetRouter);
        }
        if(cell.getCommand() != expectedCommand) {
            throw new TorException("Expecting "+ expected + " from "+ targetRouter + " and received cell command "+ cell.getCommand());
        }
        return cell;
    }

    private CircuitNode appendFirstHop(Router targetRouter, TorKeyAgreement kex, byte[] reply) {
        final byte[] keyMaterial = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
        final byte[] verifyHash = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
        if(!kex.deriveKeysFromHandshakeResponse(reply, keyMaterial, verifyHash)) {
            throw new TorException("Handshake with "+ targetRouter + " failed: bad authentication in reply");
        }
        final CircuitNode node = CircuitNodeImpl.createFirstHop(targetRouter, keyMaterial, verifyHash);
        circuit.appendNode(node);
        return node;
    }

    CircuitNode extendTo(Router targetRouter) {
        if(circuit.getCircuitLength() == 0) {
            throw new TorException("Cannot EXTEND an empty circuit");
        }
        if(targetRouter.getNTorOnionKey() == null) {
            throw new TorException("Cannot extend to "+ targetRouter.getNickname() + ": no ntor onion key known");
        }
        final NTorCircuitExtender nce = new NTorCircuitExtender(this, targetRouter);
        return nce.extendTo();
    }

    /*
     * No reply arrived: either the circuit was destroyed (a DESTROY cell from
     * a relay, or the connection closed) or the build timed out.
     */
    private TorException noResponseException(String context) {
        final String reason = circuit.getDestroyReason();
        if(reason != null) {
            return new TorException("Circuit "+ reason +" while "+ context);
        }
        return new TorException("Timeout building circuit "+ context);
    }

    private void logProtocolViolation(String sourceName, Router targetRouter) {
        final String version = (targetRouter == null) ? "(none)" : targetRouter.getVersion();
        final String targetName = (targetRouter == null) ? "(none)" : targetRouter.getNickname();
        logger.warn("Protocol error extending circuit from ("+ sourceName +") to ("+ targetName +") [version: "+ version +"]");
    }

    private String nodeToName(CircuitNode node) {
        if(node == null || node.getRouter() == null) {
            return "(null)";
        }
        final Router router = node.getRouter();
        return router.getNickname();
    }


    public void sendRelayCell(RelayCell cell) {
        circuit.sendRelayCell(cell);
    }


    public RelayCell receiveRelayResponse(int expectedCommand, Router extendTarget) {
        final RelayCell cell = circuit.receiveRelayCell();
        if(cell == null) {
            final String target = (extendTarget == null) ? "" : (" extending to "+ extendTarget.getNickname());
            throw noResponseException("waiting for "+ RelayCellImpl.commandToDescription(expectedCommand) + target);
        }
        final int command = cell.getRelayCommand();
        if(command == RelayCell.RELAY_TRUNCATED) {
            final int code = cell.getByte() & 0xFF;
            final String msg = CellImpl.errorToDescription(code);
            final String source = nodeToName(cell.getCircuitNode());
            if(code == Cell.ERROR_PROTOCOL) {
                    logProtocolViolation(source, extendTarget);
            }
            throw new TorException("Error from ("+ source +") while extending to ("+ extendTarget.getNickname() + "): "+ msg);
        } else if(command != expectedCommand) {
            final String expected = RelayCellImpl.commandToDescription(expectedCommand);
            final String received = RelayCellImpl.commandToDescription(command);
            throw new TorException("Received incorrect extend response, expecting "+ expected + " but received "+ received);
        } else {
            return cell;
        }
    }


    public CircuitNode createNewNode(Router r, byte[] keyMaterial, byte[] verifyDigest) {
        final CircuitNode node = CircuitNodeImpl.createNode(r, circuit.getFinalCircuitNode(), keyMaterial, verifyDigest);
        logger.debug("Adding new circuit node for "+ r.getNickname());
        circuit.appendNode(node);
        return node;
    }

    public RelayCell createRelayCell(int command) {
        return new RelayCellImpl(circuit.getFinalCircuitNode(), circuit.getCircuitId(), 0, command, true);
    }

    Router getFinalRouter() {
        final CircuitNode node = circuit.getFinalCircuitNode();
        if(node != null) {
            return node.getRouter();
        } else {
            return null;
        }
    }
}
