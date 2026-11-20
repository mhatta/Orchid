package com.subgraph.orchid.circuits.path;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.subgraph.orchid.Directory;
import com.subgraph.orchid.GuardInfo;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.guards.EntryGuards;
import com.subgraph.orchid.circuits.guards.VanguardsLite;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser.WeightRule;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.exitpolicy.ExitTarget;

public class CircuitPathChooser {
	
	public static CircuitPathChooser create(TorConfig config, Directory directory) {
		return new CircuitPathChooser(config, directory, new CircuitNodeChooser(config, directory));
	}

	private final Directory directory;
	private final CircuitNodeChooser nodeChooser;
	
	private EntryGuards entryGuards;
	private boolean useEntryGuards;
	private VanguardsLite vanguards;
	
	CircuitPathChooser(TorConfig config, Directory directory, CircuitNodeChooser nodeChooser) {
		this.directory = directory;
		this.nodeChooser = nodeChooser;
		this.entryGuards = null;
		this.useEntryGuards = false;
	}

	/** See {@link EntryGuards#networkChanged()}. */
	public void networkChanged() {
		if(entryGuards != null) {
			entryGuards.networkChanged();
		}
	}

	/** See {@link EntryGuards#getGuardInfo()}; an empty list without entry guards. */
	public List<GuardInfo> getEntryGuardInfo() {
		final EntryGuards guards = entryGuards;
		if(guards == null || !useEntryGuards) {
			return Collections.emptyList();
		}
		return guards.getGuardInfo();
	}

	public void enableEntryGuards(EntryGuards entryGuards) {
		this.entryGuards = entryGuards;
		this.useEntryGuards = true;
	}

	/** Use layer-2 guards (vanguards-lite) on onion service circuits. */
	public void enableVanguardsLite(VanguardsLite vanguards) {
		this.vanguards = vanguards;
	}

	/*
	 * One-hop directory requests go to a primary guard (directory guards,
	 * as in Tor), or to a bridge.  Before there is a consensus, or with
	 * entry guards off, to a directory cache, fallback directory or
	 * authority.
	 */
	public List<Router> chooseDirectoryPath() throws InterruptedException {
		if(useEntryGuards && entryGuards.isUsingBridges()) {
			final Router bridge = entryGuards.chooseDirectoryGuard();
			if(bridge == null) {
				throw new IllegalStateException("Failed to choose bridge for directory request");
			}
			return Arrays.asList(bridge);
		}
		if(useEntryGuards) {
			final Router guard = entryGuards.chooseDirectoryGuard();
			if(guard != null) {
				return Arrays.asList(guard);
			}
		}
		final Router dir = nodeChooser.chooseDirectory();
		return Arrays.asList(dir);
	}

	/*
	 * A circuit for onion service use: guard, layer-2 guard (with
	 * vanguards-lite), middle.  The middle is the rendezvous point, or the
	 * circuit is extended from it to an introduction point or HSDir.
	 */
	public List<Router> chooseInternalPath() throws InterruptedException, PathSelectionFailedException {
		if(vanguards == null) {
			final Set<Router> excluded = Collections.emptySet();
			final Router finalRouter = chooseMiddleNode(excluded);
			if(finalRouter == null) {
				throw new PathSelectionFailedException("Failed to select suitable final node for internal circuit");
			}
			return choosePathWithFinal(finalRouter);
		}
		final Set<Router> excluded = new HashSet<Router>();
		final Router entryRouter = chooseEntryNode(excluded);
		if(entryRouter == null) {
			throw new PathSelectionFailedException("Failed to select suitable entry node");
		}
		excludeChosenRouterAndRelated(entryRouter, excluded);
		final Router layer2 = vanguards.chooseLayer2(excluded);
		if(layer2 == null) {
			throw new PathSelectionFailedException("No layer-2 guard can be used with the guard "+ entryRouter.getNickname());
		}
		excludeChosenRouterAndRelated(layer2, excluded);
		final Router finalRouter = chooseMiddleNode(excluded);
		if(finalRouter == null) {
			throw new PathSelectionFailedException("Failed to select suitable final node for internal circuit");
		}
		return Arrays.asList(entryRouter, layer2, finalRouter);
	}

	/* Feedback for guard selection (guard-spec 4.7, 4.8). */

	/**
	 * The first hop of a circuit failed: the connection could not be made,
	 * or the router did not create the hop (no answer, DESTROY, a bad
	 * reply).
	 */
	public void firstHopConnectionFailed(Router firstHop) {
		if(useEntryGuards) {
			entryGuards.guardConnectionFailed(firstHop);
		}
	}

	/** The first hop of a circuit was created. */
	public void firstHopCreated(Router firstHop) {
		if(useEntryGuards) {
			entryGuards.guardReachable(firstHop);
		}
	}

	/**
	 * A circuit that will carry user traffic (not a directory request) was
	 * built.  Returns false if it should not be used, because a better
	 * guard may be reachable (guard-spec 4.9).
	 */
	public boolean circuitBuiltForUse(Router firstHop) {
		if(useEntryGuards) {
			return entryGuards.circuitBuilt(firstHop);
		}
		return true;
	}

	public List<Router> choosePathWithExit(Router exitRouter) throws InterruptedException, PathSelectionFailedException {
		return choosePathWithFinal(exitRouter);
	}

	public List<Router> choosePathWithFinal(Router finalRouter) throws InterruptedException, PathSelectionFailedException {
		if(finalRouter == null) {
			throw new PathSelectionFailedException("No final node given for circuit path");
		}
		final Set<Router> excluded = new HashSet<Router>();
		excludeChosenRouterAndRelated(finalRouter, excluded);

		final Router middleRouter = chooseMiddleNode(excluded);
		if(middleRouter == null) {
			throw new PathSelectionFailedException("Failed to select suitable middle node");
		}
		excludeChosenRouterAndRelated(middleRouter, excluded);

		final Router entryRouter = chooseEntryNode(excluded);
		if(entryRouter == null) {
			throw new PathSelectionFailedException("Failed to select suitable entry node");
		}
		return Arrays.asList(entryRouter, middleRouter, finalRouter);
	}

	public Router chooseEntryNode(final Set<Router> excludedRouters) throws InterruptedException {
		if(useEntryGuards) {
			return entryGuards.chooseRandomGuard(excludedRouters);
		}

		return nodeChooser.chooseRandomNode(WeightRule.WEIGHT_FOR_GUARD, new RouterFilter() {
			public boolean filter(Router router) {
				return router.isPossibleGuard() && !excludedRouters.contains(router);
			}
		});
	}

	Router chooseMiddleNode(final Set<Router> excludedRouters) {
		return nodeChooser.chooseRandomNode(WeightRule.WEIGHT_FOR_MID, new RouterFilter() {
			public boolean filter(Router router) {
				return router.isFast() && !excludedRouters.contains(router);
			}
		});
	}

	public Router chooseExitNodeForTargets(List<ExitTarget> targets) {
		final List<Router> routers = filterForExitTargets(
				getUsableExitRouters(), targets);
		return nodeChooser.chooseExitNode(routers);
	}
	
	private List<Router> getUsableExitRouters() {
		final List<Router> result = new ArrayList<Router>();
		for(Router r: nodeChooser.getUsableRouters(true)) {
			if(r.isExit() && !r.isBadExit()) {
				result.add(r);
			}
		}
		return result;
	}

	private void excludeChosenRouterAndRelated(Router router, Set<Router> excludedRouters) {
		excludedRouters.add(router);
		for(Router r: directory.getAllRouters()) {
			if(areInSameSlash16(router, r) || shareFamilyId(router, r)) {
				excludedRouters.add(r);
			}
		}
		
		for(String s: router.getFamilyMembers()) {
			Router r = directory.getRouterByName(s);
			if(r != null) {
				// Is mutual?
				if(isFamilyMember(r.getFamilyMembers(), router)) {
					excludedRouters.add(r);
				}
			}
		}
	}

	/**
	 * Whether two routers must not be on the same circuit: the same router,
	 * routers in the same family, or routers in the same /16 network, as in
	 * Tor (nodes_in_same_family()).
	 *
	 * Two routers are in the same family if each lists the other in its
	 * <code>family</code> line, or, with Happy Families (proposal 321), if
	 * they share a family ID.  Tor 0.4.9 relays prove their family with a
	 * family key, and the <code>family</code> lines are to be dropped once
	 * enough clients understand family IDs; without them, two relays of
	 * one operator would no longer be kept apart.
	 */
	public boolean areRelated(Router r1, Router r2) {
		if(r1 == null || r2 == null) {
			return false;
		}
		if(r1.equals(r2) || areInSameSlash16(r1, r2) || shareFamilyId(r1, r2)) {
			return true;
		}
		return isFamilyMember(r1.getFamilyMembers(), r2) && isFamilyMember(r2.getFamilyMembers(), r1);
	}

	static boolean shareFamilyId(Router r1, Router r2) {
		final Set<String> ids1 = r1.getFamilyIds();
		final Set<String> ids2 = r2.getFamilyIds();
		if(ids1 == null || ids2 == null || ids1.isEmpty() || ids2.isEmpty()) {
			return false;
		}
		for(String id: ids1) {
			if(ids2.contains(id)) {
				return true;
			}
		}
		return false;
	}
	
	private boolean isFamilyMember(Collection<String> familyMemberNames, Router r) {
		if(familyMemberNames == null) {
			return false;
		}
		for(String s: familyMemberNames) {
			Router member = directory.getRouterByName(s);
			if(member != null && member.equals(r)) {
				return true;
			}
		}
		return false;
	}

	// Are routers r1 and r2 in the same /16 network
	private boolean areInSameSlash16(Router r1, Router r2) {
		final IPv4Address a1 = r1.getAddress();
		final IPv4Address a2 = r2.getAddress();
		if(a1 == null || a2 == null) {
			return false;
		}
		final int mask = 0xFFFF0000;
		return (a1.getAddressData() & mask) == (a2.getAddressData() & mask);
	}
	
	private List<Router> filterForExitTargets(List<Router> routers, List<ExitTarget> exitTargets) {
		int bestSupport = 0;
		if(exitTargets.isEmpty()) {
			return routers;
		}
		
		final int[] nSupport = new int[routers.size()];
		
		for(int i = 0; i < routers.size(); i++) {
			final Router r = routers.get(i);
			nSupport[i] = countTargetSupport(r, exitTargets);
			if(nSupport[i] > bestSupport) {
				bestSupport = nSupport[i];
			}
		}
		
		if(bestSupport == 0) {
			return routers;
		}

		final List<Router> results = new ArrayList<Router>();
		for(int i = 0; i < routers.size(); i++) {
			if(nSupport[i] == bestSupport) {
				results.add(routers.get(i));
			}
		}
		return results;
	}

	private int countTargetSupport(Router router, List<ExitTarget> targets) {
		int count = 0;
		for(ExitTarget t: targets) {
			if(routerSupportsTarget(router, t)) {
				count += 1;
			}
		}
		return count;
	}

	private boolean routerSupportsTarget(Router router, ExitTarget target) {
		if(target.isAddressTarget()) {
			return router.exitPolicyAccepts(target.getAddress(), target.getPort());
		} else {
			return router.exitPolicyAccepts(target.getPort());
		}
	}
}
