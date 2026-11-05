package com.subgraph.orchid.directory;

import java.io.File;

import com.subgraph.orchid.TorException;

/**
 * Checks and creates the data directory, where Orchid keeps the state file
 * (its entry guards) and its directory caches.
 *
 * Without a usable data directory Orchid used to log a warning and run
 * without saving anything.  Its entry guards were then chosen anew on every
 * start, which defeats the purpose of entry guards: an adversary who runs
 * some guards gets a new chance to be picked each time.  On Android, where
 * the default <code>~/.orchid</code> cannot be created and processes are
 * restarted often, that was the normal case.  Orchid now refuses to start
 * instead.
 */
public final class DataDirectory {
	private DataDirectory() {}

	/**
	 * Make sure that <code>directory</code> exists, is a directory and is
	 * writable, creating it if it is missing, and make it accessible to its
	 * owner only.
	 *
	 * @throws TorException with an explanation if it is not set or not usable.
	 */
	public static void prepare(File directory) {
		if(directory == null) {
			throw new TorException("No data directory is set.  Call TorConfig#setDataDirectory() before starting "
					+ "Orchid; on Android use a folder under Context#getNoBackupFilesDir(), which is private to the "
					+ "application and left out of backups.");
		}
		if(!directory.exists()) {
			if(!directory.mkdirs()) {
				throw new TorException("Cannot create the data directory "+ directory
						+ ".  Set a writable one with TorConfig#setDataDirectory().");
			}
		}
		if(!directory.isDirectory()) {
			throw new TorException("The data directory "+ directory +" is not a directory");
		}
		if(!directory.canWrite()) {
			throw new TorException("The data directory "+ directory +" is not writable");
		}
		/*
		 * Also when the directory already exists: it may have been created by
		 * an earlier version, which did not restrict it, or by hand.  Tor
		 * fixes the permissions of its data directory in the same way.
		 */
		restrictToOwner(directory);
	}

	/*
	 * The data directory reveals the entry guards.  java.io.File is used
	 * rather than java.nio.file, which Android has only from API level 26.
	 */
	private static void restrictToOwner(File directory) {
		directory.setReadable(false, false);
		directory.setReadable(true, true);
		directory.setWritable(false, false);
		directory.setWritable(true, true);
		directory.setExecutable(false, false);
		directory.setExecutable(true, true);
	}
}
