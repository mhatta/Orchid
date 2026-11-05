package com.subgraph.orchid.directory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.TorException;

public class DataDirectoryTest {
	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	private static void assertRejected(File dir, String messagePart) {
		try {
			DataDirectory.prepare(dir);
			fail("expected TorException");
		} catch(TorException e) {
			assertTrue(e.getMessage(), e.getMessage().contains(messagePart));
		}
	}

	@Test
	public void testNotSet() {
		assertRejected(null, "No data directory");
	}

	@Test
	public void testCreatedForOwnerOnly() throws IOException {
		final File dir = new File(tmp.getRoot(), "a/b/orchid");
		DataDirectory.prepare(dir);
		assertTrue(dir.isDirectory());
		Assume.assumeTrue(Files.getFileStore(dir.toPath()).supportsFileAttributeView("posix"));
		final Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dir.toPath());
		assertEquals(PosixFilePermissions.fromString("rwx------"), perms);
	}

	@Test
	public void testExistingDirectoryIsAccepted() throws IOException {
		DataDirectory.prepare(tmp.newFolder("existing"));
	}

	@Test
	public void testExistingDirectoryIsRestrictedToOwner() throws IOException {
		final File dir = tmp.newFolder("open");
		Assume.assumeTrue(Files.getFileStore(dir.toPath()).supportsFileAttributeView("posix"));
		Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("rwxr-xr-x"));
		DataDirectory.prepare(dir);
		assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(dir.toPath()));
	}

	@Test
	public void testCannotCreate() throws IOException {
		// A path below a regular file cannot be created.
		final File file = tmp.newFile("plain");
		assertRejected(new File(file, "orchid"), "Cannot create");
	}

	@Test
	public void testNotADirectory() throws IOException {
		assertRejected(tmp.newFile("plain2"), "not a directory");
	}

	@Test
	public void testNotWritable() throws IOException {
		final File dir = tmp.newFolder("readonly");
		assertTrue(dir.setWritable(false, false));
		Assume.assumeTrue("running as root, which can write anywhere", !dir.canWrite());
		assertRejected(dir, "not writable");
	}

	@Test
	public void testTorClientRefusesToStartWithoutDataDirectory() throws IOException {
		final TorClient client = new TorClient();
		client.getConfig().setDataDirectory(new File(tmp.newFile("plain3"), "orchid"));
		try {
			client.start();
			fail("expected TorException");
		} catch(TorException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("Cannot create"));
		} finally {
			client.stop();
		}
	}
}
