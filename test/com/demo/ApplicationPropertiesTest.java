package com.demo;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.junit.Test;

public class ApplicationPropertiesTest {

	private static InputStream text(String s) {
		return new ByteArrayInputStream(s.getBytes());
	}

	@Test
	public void testReleaseVersion() {
		assertEquals("2.0.0", ApplicationProperties.parseVersion(text("# comment\nversion=2.0.0\n")));
	}

	@Test
	public void testDevelopmentVersion() {
		assertEquals("2.0.0-3-g1234abcd-dirty",
				ApplicationProperties.parseVersion(text("version=2.0.0-3-g1234abcd-dirty\n")));
	}

	/* The unfiltered resource, e.g. when the classes were not built with Gradle. */
	@Test
	public void testUnfilteredResourceIsUnknown() {
		assertEquals(ApplicationProperties.UNKNOWN_VERSION, ApplicationProperties.parseVersion(text("version=\n")));
		assertEquals(ApplicationProperties.UNKNOWN_VERSION, ApplicationProperties.parseVersion(text("")));
	}

	/* The version is stored as a single token in the state file. */
	@Test
	public void testVersionWithSpaceIsRejected() {
		assertEquals(ApplicationProperties.UNKNOWN_VERSION, ApplicationProperties.parseVersion(text("version=2.0 beta\n")));
	}
}
