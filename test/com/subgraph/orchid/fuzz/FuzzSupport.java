package com.subgraph.orchid.fuzz;

import com.subgraph.orchid.logging.LogHandler;
import com.subgraph.orchid.logging.Logger;
import com.subgraph.orchid.logging.SysLog;

/**
 * Shared by the fuzz targets (the classes named *Fuzzer).  Each target has
 * the entry point Jazzer calls, {@code public static void
 * fuzzerTestOneInput(byte[] data)}, and nothing else of Jazzer's, so that
 * the test sources build without it.  An exception that leaves a target
 * is a finding: the targets catch only the exceptions by which the code
 * under test refuses bad input.
 *
 * <pre>
 * ./gradlew testClasses
 * jazzer --cp=build/classes/java/main:build/classes/java/test \
 *     --target_class=com.subgraph.orchid.directory.ConsensusFuzzer \
 *     test/fuzz/corpus/consensus -- -max_total_time=60
 * </pre>
 *
 * The CI workflow fuzz.yml runs every target that way.
 */
public final class FuzzSupport {
	private FuzzSupport() {}

	private static volatile boolean quiet;

	/* Parsers log what they refuse; at fuzzing speed that is all the fuzzer would do. */
	public static void quietLogging() {
		if(quiet) {
			return;
		}
		Logger.setHandler(new LogHandler() {
			public void log(SysLog level, String name, String message, Throwable throwable) {
			}
		});
		quiet = true;
	}
}
