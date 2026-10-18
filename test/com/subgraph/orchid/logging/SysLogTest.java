package com.subgraph.orchid.logging;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import org.junit.Test;

public class SysLogTest {

	@Test
	public void testForName() {
		assertSame(SysLog.DEBUG, SysLog.forName("debug"));
		assertSame(SysLog.DEBUG, SysLog.forName(" DEBUG "));
		assertSame(SysLog.INFORMATIONAL, SysLog.forName("INFO"));
		assertSame(SysLog.INFORMATIONAL, SysLog.forName("informational"));
		assertSame(SysLog.WARNING, SysLog.forName("warn"));
		assertSame(SysLog.NOTICE, SysLog.forName("Notice"));
		assertSame(SysLog.ERROR, SysLog.forName("error"));
		assertNull(SysLog.forName("verbose"));
		assertNull(SysLog.forName(null));
	}
}
