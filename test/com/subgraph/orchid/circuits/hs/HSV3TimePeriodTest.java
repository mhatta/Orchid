package com.subgraph.orchid.circuits.hs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class HSV3TimePeriodTest {

	@Test
	public void testPeriodNumberVectors() {
		/* tor test_hs_common.c: 1973-05-20 01:50:33 UTC is time period 1234 */
		assertEquals(1234, new HSV3TimePeriod(106710633L, 1440, 3600).getPeriodNumber());
		/* rend-spec-v3 [TIME-PERIODS] example: 2016-04-13 11:15:01 UTC is time period 16903 */
		assertEquals(16903, new HSV3TimePeriod(1460546101L, 1440, 3600).getPeriodNumber());
		/* ... and that period started at 2016-04-12 12:00 UTC */
		assertEquals(1460462400L, HSV3TimePeriod.startOfPeriod(16903, 1440, 720));
		/* 12:00 UTC is the first second of a new period, 11:59:59 belongs to the previous one */
		assertEquals(16904, new HSV3TimePeriod(1460548800L, 1440, 3600).getPeriodNumber());
		assertEquals(16903, new HSV3TimePeriod(1460548799L, 1440, 3600).getPeriodNumber());
	}

	@Test
	public void testBetweenTpAndSrv() {
		/* 2024-01-10 13:00 UTC: after TP start (12:00), before next SRV (00:00) -> use current SRV */
		assertTrue(new HSV3TimePeriod(1704891600L, 1440, 3600).isBetweenTpAndSrv());
		/* 2024-01-10 12:00 UTC: exactly at TP start */
		assertTrue(new HSV3TimePeriod(1704888000L, 1440, 3600).isBetweenTpAndSrv());
		/* 2024-01-11 01:00 UTC: after SRV (00:00), before next TP (12:00) -> use previous SRV */
		assertFalse(new HSV3TimePeriod(1704934800L, 1440, 3600).isBetweenTpAndSrv());
		/* 2024-01-11 00:00 UTC: exactly at SRV start */
		assertFalse(new HSV3TimePeriod(1704931200L, 1440, 3600).isBetweenTpAndSrv());
		/* 2024-01-10 11:59:59 UTC */
		assertFalse(new HSV3TimePeriod(1704887999L, 1440, 3600).isBetweenTpAndSrv());
	}
}
