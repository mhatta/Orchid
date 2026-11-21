package com.subgraph.orchid.directory.downloader;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.subgraph.orchid.config.TorConfigImpl;

/**
 * While dormant the directory download loop sleeps until it is woken up,
 * instead of waking every five seconds, and checks at once on waking.
 */
public class DirectoryDormancyTest {

	@Test(timeout = 20000)
	public void testDormantLoopWaitsUntilWokenUp() throws Exception {
		final DirectoryDownloadTask task = new DirectoryDownloadTask(new TorConfigImpl(), null, null);
		task.setDormant(true);
		final CountDownLatch returned = new CountDownLatch(1);
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					task.waitForNextCheck();
					returned.countDown();
				} catch (InterruptedException e) {
					// fails below
				}
			}
		});
		t.start();
		assertFalse("returned while dormant", returned.await(500, TimeUnit.MILLISECONDS));
		task.setDormant(false);
		assertTrue("not woken up", returned.await(2, TimeUnit.SECONDS));
	}

	@Test(timeout = 20000)
	public void testStopInterruptsTheDormantWait() throws Exception {
		final DirectoryDownloadTask task = new DirectoryDownloadTask(new TorConfigImpl(), null, null);
		task.setDormant(true);
		final CountDownLatch interrupted = new CountDownLatch(1);
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					task.waitForNextCheck();
				} catch (InterruptedException e) {
					interrupted.countDown();
				}
			}
		});
		t.start();
		Thread.sleep(200);
		task.stop();
		t.interrupt();
		assertTrue(interrupted.await(2, TimeUnit.SECONDS));
	}

	@Test
	public void testDownloaderRemembersDormancyBeforeStart() {
		final DirectoryDownloaderImpl d = new DirectoryDownloaderImpl(new TorConfigImpl(), null);
		d.setDormant(true);
		assertTrue(d.isDormant());
		d.setDormant(false);
		assertFalse(d.isDormant());
	}
}
