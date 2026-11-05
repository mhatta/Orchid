package com.subgraph.orchid.circuits;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.ExitCircuit;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.circuits.path.CircuitPathChooser;
import com.subgraph.orchid.circuits.path.PathSelectionFailedException;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.exitpolicy.ExitTarget;

public class ExitCircuitImpl extends CircuitImpl implements ExitCircuit {
	
	private final Router exitRouter;
	private final Set<ExitTarget> failedExitRequests;

	/*
	 * Stream isolation: the first exit stream request handed to this
	 * circuit claims it for its isolation key, and from then on only
	 * requests with the same key (null included) may use it.
	 */
	private final Object isolationLock = new Object();
	private boolean isolationClaimed;
	private String isolationKey;

	ExitCircuitImpl(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
		super(circuitManager, prechosenPath);
		this.exitRouter = prechosenPath.get(prechosenPath.size() - 1);
		this.failedExitRequests = new HashSet<ExitTarget>();
	}

	ExitCircuitImpl(CircuitManagerImpl circuitManager, Router exitRouter) {
		super(circuitManager);
		this.exitRouter = exitRouter;
		this.failedExitRequests = new HashSet<ExitTarget>();
	}
	
	public Stream openExitStream(IPv4Address address, int port, long timeout) throws InterruptedException, TimeoutException, StreamConnectFailedException {
		return openExitStream(address.toString(), port, timeout);
	}

	public Stream openExitStream(String target, int port, long timeout) throws InterruptedException, TimeoutException, StreamConnectFailedException {
		final StreamImpl stream = createNewStream();
		try {
			stream.openExit(target, port, timeout);
			return stream;
		} catch (Exception e) {
			removeStream(stream);
			return processStreamOpenException(e);
		}
	}
	
	public void recordFailedExitTarget(ExitTarget target) {
		synchronized(failedExitRequests) {
			failedExitRequests.add(target);
		}
	}

	/**
	 * Claim this circuit for streams with the given isolation key, if it
	 * has not been claimed for another key yet.
	 *
	 * @return true if streams with this key may use the circuit
	 */
	boolean claimIsolation(String key) {
		synchronized(isolationLock) {
			if(!isolationClaimed) {
				isolationClaimed = true;
				isolationKey = key;
				return true;
			}
			return sameKey(isolationKey, key);
		}
	}

	/** The isolation key this circuit was claimed for, or null if none (or the null key). */
	String getClaimedIsolationKey() {
		synchronized(isolationLock) {
			return isolationClaimed ? isolationKey : null;
		}
	}

	boolean isIsolationCompatible(String key) {
		synchronized(isolationLock) {
			return !isolationClaimed || sameKey(isolationKey, key);
		}
	}

	private static boolean sameKey(String a, String b) {
		return (a == null) ? (b == null) : a.equals(b);
	}

	public boolean canHandleExitTo(ExitTarget target) {
		if(target instanceof StreamExitRequest && !isIsolationCompatible(((StreamExitRequest) target).getIsolationKey())) {
			return false;
		}
		synchronized(failedExitRequests) {
			if(failedExitRequests.contains(target)) {
				return false;
			}
		}
		
		if(isMarkedForClose()) {
			return false;
		}

		if(target.isAddressTarget()) {
			return exitRouter.exitPolicyAccepts(target.getAddress(), target.getPort());
		} else {
			return exitRouter.exitPolicyAccepts(target.getPort());
		}
	}
	
	public boolean canHandleExitToPort(int port) {
		return exitRouter.exitPolicyAccepts(port);
	}

	
	@Override
	protected List<Router> choosePathForCircuit(CircuitPathChooser pathChooser) throws InterruptedException, PathSelectionFailedException {
		return pathChooser.choosePathWithExit(exitRouter);
	}
	
	@Override
	protected String getCircuitTypeLabel() {
		return "Exit";
	}
}
