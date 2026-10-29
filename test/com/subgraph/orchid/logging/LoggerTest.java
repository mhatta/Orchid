package com.subgraph.orchid.logging;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.ApplicationProperties;

public class LoggerTest {
	private static final Logger logger = Logger.getInstance(LoggerTest.class);

	private static class Entry {
		final SysLog level;
		final String name;
		final String message;
		final Throwable throwable;
		Entry(SysLog level, String name, String message, Throwable throwable) {
			this.level = level;
			this.name = name;
			this.message = message;
			this.throwable = throwable;
		}
	}

	private final List<Entry> entries = new ArrayList<Entry>();
	private SysLog savedThreshold;

	@Before
	public void before() {
		savedThreshold = ApplicationProperties.getLoggingThreshold();
		Logger.setHandler(new LogHandler() {
			public void log(SysLog level, String name, String message, Throwable throwable) {
				entries.add(new Entry(level, name, message, throwable));
			}
		});
	}

	@After
	public void after() {
		Logger.setHandler(null);
		ApplicationProperties.setLoggingThreshold(savedThreshold);
	}

	@Test
	public void testMessagesGoToTheHandler() {
		ApplicationProperties.setLoggingThreshold(SysLog.DEBUG);
		final IOException e = new IOException("boom");
		logger.debug("d");
		logger.info("i");
		logger.warn("w", e);
		logger.error(null);
		logger.fatal("f");
		assertEquals(5, entries.size());
		assertSame(SysLog.DEBUG, entries.get(0).level);
		assertEquals("LoggerTest", entries.get(0).name);
		assertEquals("d", entries.get(0).message);
		assertNull(entries.get(0).throwable);
		assertSame(SysLog.INFORMATIONAL, entries.get(1).level);
		assertSame(SysLog.WARNING, entries.get(2).level);
		assertSame(e, entries.get(2).throwable);
		assertEquals("", entries.get(3).message);
		assertSame(SysLog.EMERGENCY, entries.get(4).level);
	}

	@Test
	public void testThresholdIsApplied() {
		ApplicationProperties.setLoggingThreshold(SysLog.WARNING);
		assertFalse(logger.isDebugEnabled());
		logger.debug("d");
		logger.info("i");
		logger.warn("w");
		assertEquals(1, entries.size());
		assertEquals("w", entries.get(0).message);
	}

	@Test
	public void testFailingHandlerIsIgnored() {
		ApplicationProperties.setLoggingThreshold(SysLog.DEBUG);
		Logger.setHandler(new LogHandler() {
			public void log(SysLog level, String name, String message, Throwable throwable) {
				throw new IllegalStateException();
			}
		});
		logger.error("must not throw");
		assertTrue(logger.isDebugEnabled());
	}

	@Test
	public void testNullRestoresConsole() {
		Logger.setHandler(null);
		assertSame(ConsoleLogHandler.INSTANCE, Logger.getHandler());
		assertEquals("FATAL", ConsoleLogHandler.label(SysLog.EMERGENCY));
		assertEquals("ERROR", ConsoleLogHandler.label(SysLog.ERROR));
		assertEquals("WARN", ConsoleLogHandler.label(SysLog.WARNING));
		assertEquals("INFO", ConsoleLogHandler.label(SysLog.INFORMATIONAL));
		assertEquals("DEBUG", ConsoleLogHandler.label(SysLog.DEBUG));
	}
}
