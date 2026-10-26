package com.subgraph.orchid.data;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


public class RandomSet<E> {
	
	private final Set<E> set;
	private final List<E> list;
	private final SecureRandom random;
	
	public RandomSet() {
		set = new HashSet<E>();
		list = new ArrayList<E>();
		random = createRandom();
	}
	
	/*
	 * The platform's default generator (NativePRNG or DRBG on the JDK,
	 * Conscrypt's on Android), seeded from the operating system.  Orchid
	 * asked for "SHA1PRNG" by name before: a legacy algorithm whose
	 * implementation and seeding differ between providers, and whose flawed
	 * seeding on early Android releases exposed private keys in other
	 * applications.
	 */
	private static SecureRandom createRandom() {
		return new SecureRandom();
	}
	
	public boolean add(E o) {
		if(set.add(o)) {
			list.add(o);
			return true;
		} else {
			return false;
		}
	}
	
	public boolean contains(Object o) {
		return set.contains(o);
	}
	
	public boolean isEmpty() {
		return set.isEmpty();
	}
	
	public void clear() {
		set.clear();
		list.clear();
	}
	
	public boolean remove(Object o) {
		if(set.remove(o)) {
			list.remove(o);
			return true;
		} else {
			return false;
		}
	}
	
	public int size() {
		return set.size();
	}
	
	public E getRandomElement() {
		int idx = random.nextInt(list.size());
		return list.get(idx);
	}

}
