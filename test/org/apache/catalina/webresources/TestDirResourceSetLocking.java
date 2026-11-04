/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.webresources;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.WebResource;
import org.apache.catalina.WebResourceLockSet.ResourceLock;
import org.apache.catalina.startup.ExpandWar;

/**
 * Tests the resource locking added to {@link DirResourceSet} and
 * {@link FileResource} to close the read / write race condition exploited by
 * CVE-2024-50379.
 * <p>
 * Without the locking, a concurrent read (HTTP GET) and write (HTTP PUT /
 * DELETE via the write enabled DefaultServlet) of the same path can produce a
 * {@link FileResource} where some fields are populated as if the file exists
 * and others as if it does not. On a case insensitive file system that
 * inconsistent view allows an uploaded file to be compiled and executed as a
 * JSP.
 */
public class TestDirResourceSetLocking {

    /*
     * How long to wait when confirming that a lock is *not* granted. Since the
     * lock genuinely cannot be granted while the conflicting lock is held, this
     * only needs to be long enough for the competing thread to reach the lock.
     */
    private static final long BLOCKED_MS = 500;

    /* Generous timeout used when a lock is expected to be granted. */
    private static final long GRANTED_MS = 20_000;

    private File tempDir;
    private TesterWebResourceRoot root;
    private DirResourceSet dirResourceSet;

    @Before
    public void before() throws IOException {
        Path tempDirPath = Files.createTempDirectory("test-locking", new FileAttribute[0]);
        tempDir = tempDirPath.toFile();
        root = new TesterWebResourceRoot();
        /*
         * As in the sibling tests in this package, the DirResourceSet is started
         * by its own constructor because TesterWebResourceRoot reports an
         * available state. That matters here because initInternal() is what
         * determines whether the file system is case sensitive, which in turn
         * determines how the lock keys are built.
         */
        dirResourceSet = new DirResourceSet(root, "/", tempDir.getAbsolutePath(), "/");
        Assert.assertEquals("The DirResourceSet must be started so that initInternal() has run",
                LifecycleState.STARTED, dirResourceSet.getState());
        dirResourceSet.setReadOnly(false);
        root.setMainResources(dirResourceSet);
    }


    @After
    public void after() {
        if (tempDir != null) {
            ExpandWar.delete(tempDir);
        }
    }


    /*
     * The ResourceLock instances must be shared for the duration of their use
     * and removed from the internal map once the usage count drops to zero,
     * otherwise the map is an unbounded memory leak.
     */
    @Test
    public void testReadLockRefCounting() {
        ResourceLock lock1 = dirResourceSet.lockForRead("/ref-count.txt");
        Assert.assertEquals("/ref-count.txt", lock1.key);
        Assert.assertEquals(1, lock1.count.get());

        ResourceLock lock2 = dirResourceSet.lockForRead("/ref-count.txt");
        Assert.assertSame("Concurrent locks for the same path must share a ResourceLock", lock1, lock2);
        Assert.assertEquals(2, lock1.count.get());

        dirResourceSet.unlockForRead(lock2);
        Assert.assertEquals(1, lock1.count.get());

        dirResourceSet.unlockForRead(lock1);
        Assert.assertEquals(0, lock1.count.get());

        /*
         * The usage count reached zero so the entry must have been removed from
         * the internal map. Locking the same path again therefore has to return
         * a brand new ResourceLock.
         */
        ResourceLock lock3 = dirResourceSet.lockForRead("/ref-count.txt");
        Assert.assertNotSame("ResourceLock was not removed from the map when no longer in use", lock1, lock3);
        Assert.assertEquals(1, lock3.count.get());
        dirResourceSet.unlockForRead(lock3);
        Assert.assertEquals(0, lock3.count.get());
    }


    @Test
    public void testWriteLockRefCounting() {
        ResourceLock lock1 = dirResourceSet.lockForWrite("/ref-count-w.txt");
        Assert.assertEquals(1, lock1.count.get());

        ResourceLock lock2 = dirResourceSet.lockForWrite("/ref-count-w.txt");
        Assert.assertSame(lock1, lock2);
        Assert.assertEquals(2, lock1.count.get());

        dirResourceSet.unlockForWrite(lock2);
        dirResourceSet.unlockForWrite(lock1);
        Assert.assertEquals(0, lock1.count.get());

        ResourceLock lock3 = dirResourceSet.lockForWrite("/ref-count-w.txt");
        Assert.assertNotSame(lock1, lock3);
        dirResourceSet.unlockForWrite(lock3);
    }


    /* Different paths must not contend with each other. */
    @Test
    public void testDifferentPathsUseDifferentLocks() {
        ResourceLock lock1 = dirResourceSet.lockForWrite("/one.txt");
        ResourceLock lock2 = dirResourceSet.lockForWrite("/two.txt");
        Assert.assertNotSame(lock1, lock2);
        dirResourceSet.unlockForWrite(lock2);
        dirResourceSet.unlockForWrite(lock1);
    }


    /*
     * The lock key is normalized so that two spellings of the same path can
     * never end up using two different locks (which would leave the race open).
     */
    @Test
    public void testLockKeyIsNormalized() {
        ResourceLock lock1 = dirResourceSet.lockForRead("/dir/sub/../target.txt");
        ResourceLock lock2 = dirResourceSet.lockForRead("/dir/./target.txt");
        try {
            Assert.assertEquals("/dir/target.txt", lock1.key);
            Assert.assertSame("Equivalent paths must share a ResourceLock", lock1, lock2);
        } finally {
            dirResourceSet.unlockForRead(lock2);
            dirResourceSet.unlockForRead(lock1);
        }
    }


    /*
     * CVE-2024-50379 is only exploitable on a case insensitive file system, so
     * on such a file system paths that differ only in case must share a lock.
     * On a case sensitive file system they refer to different files and must
     * not contend.
     *
     * This asserts against the case sensitivity DirResourceSet actually
     * determined for itself in initInternal(), so it holds on any host file
     * system. The two branches are additionally covered deterministically by
     * testLockKeyIsCaseFolded...() / testLockKeyIsNotCaseFolded...() below.
     */
    @Test
    public void testLockKeyCaseSensitivityFollowsFileSystem() throws Exception {
        File lower = new File(tempDir, "case-test.jsp");
        Assert.assertTrue(lower.createNewFile());

        ResourceLock lock1 = dirResourceSet.lockForRead("/case-test.jsp");
        ResourceLock lock2 = dirResourceSet.lockForRead("/CASE-TEST.JSP");
        try {
            if (isCaseSensitive(dirResourceSet)) {
                Assert.assertNotSame("On a case sensitive file system paths differing only in case refer to " +
                        "different files so they must not share a ResourceLock", lock1, lock2);
            } else {
                Assert.assertSame("On a case insensitive file system paths differing only in case refer to " +
                        "the same file so they must share a ResourceLock", lock1, lock2);
            }
        } finally {
            dirResourceSet.unlockForRead(lock2);
            dirResourceSet.unlockForRead(lock1);
        }
    }


    /*
     * The case insensitive branch of the lock key calculation is the one that
     * matters for CVE-2024-50379 but it cannot be reached on a case sensitive
     * host file system, so drive it directly. Building the key is pure string
     * manipulation and does not touch the file system, so forcing the flag is
     * safe and deterministic on any host.
     */
    @Test
    public void testLockKeyIsCaseFoldedWhenFileSystemIsCaseInsensitive() throws Exception {
        setCaseSensitive(dirResourceSet, false);

        // The key is normalized *and* lower cased.
        ResourceLock lock1 = dirResourceSet.lockForRead("/sub/../MiXeD.JSP");
        ResourceLock lock2 = dirResourceSet.lockForRead("/mixed.jsp");
        try {
            Assert.assertEquals("/mixed.jsp", lock1.key);
            Assert.assertSame("Paths differing only in case must share a ResourceLock when the file system " +
                    "is case insensitive", lock1, lock2);
        } finally {
            dirResourceSet.unlockForRead(lock2);
            dirResourceSet.unlockForRead(lock1);
        }

        /*
         * The security relevant consequence: a read of one spelling and a write
         * of another spelling of the same file are mutually exclusive.
         */
        ResourceLock held = dirResourceSet.lockForRead("/mixed.jsp");
        CountDownLatch acquired = new CountDownLatch(1);
        Thread t = startLockThread(acquired, false, "/MIXED.JSP");
        try {
            Assert.assertFalse("A write of /MIXED.JSP must not proceed while /mixed.jsp is being read on a " +
                    "case insensitive file system", acquired.await(BLOCKED_MS, TimeUnit.MILLISECONDS));
        } finally {
            dirResourceSet.unlockForRead(held);
        }
        Assert.assertTrue(acquired.await(GRANTED_MS, TimeUnit.MILLISECONDS));
        t.join(GRANTED_MS);
    }


    /* The complementary branch: no case folding on a case sensitive file system. */
    @Test
    public void testLockKeyIsNotCaseFoldedWhenFileSystemIsCaseSensitive() throws Exception {
        setCaseSensitive(dirResourceSet, true);

        ResourceLock lock1 = dirResourceSet.lockForRead("/sub/../MiXeD.JSP");
        ResourceLock lock2 = dirResourceSet.lockForRead("/mixed.jsp");
        try {
            Assert.assertEquals("/MiXeD.JSP", lock1.key);
            Assert.assertNotSame("Paths differing only in case refer to different files when the file system " +
                    "is case sensitive so they must not share a ResourceLock", lock1, lock2);
        } finally {
            dirResourceSet.unlockForRead(lock2);
            dirResourceSet.unlockForRead(lock1);
        }
    }


    /* Read locks are not exclusive. */
    @Test
    public void testReadLockDoesNotBlockReadLock() throws Exception {
        ResourceLock held = dirResourceSet.lockForRead("/shared.txt");
        try {
            CountDownLatch acquired = new CountDownLatch(1);
            Thread t = startLockThread(acquired, true, "/shared.txt");
            Assert.assertTrue("A read lock must not block another read lock", acquired.await(GRANTED_MS,
                    TimeUnit.MILLISECONDS));
            t.join(GRANTED_MS);
        } finally {
            dirResourceSet.unlockForRead(held);
        }
    }


    /* Write locks are exclusive with respect to read locks. */
    @Test
    public void testWriteLockBlocksReadLock() throws Exception {
        ResourceLock held = dirResourceSet.lockForWrite("/exclusive.txt");
        CountDownLatch acquired = new CountDownLatch(1);
        Thread t = startLockThread(acquired, true, "/exclusive.txt");
        try {
            Assert.assertFalse("A read lock must not be granted while a write lock is held",
                    acquired.await(BLOCKED_MS, TimeUnit.MILLISECONDS));
        } finally {
            dirResourceSet.unlockForWrite(held);
        }
        Assert.assertTrue("The read lock must be granted once the write lock is released",
                acquired.await(GRANTED_MS, TimeUnit.MILLISECONDS));
        t.join(GRANTED_MS);
    }


    /* Read locks are exclusive with respect to write locks. */
    @Test
    public void testReadLockBlocksWriteLock() throws Exception {
        ResourceLock held = dirResourceSet.lockForRead("/exclusive2.txt");
        CountDownLatch acquired = new CountDownLatch(1);
        Thread t = startLockThread(acquired, false, "/exclusive2.txt");
        try {
            Assert.assertFalse("A write lock must not be granted while a read lock is held",
                    acquired.await(BLOCKED_MS, TimeUnit.MILLISECONDS));
        } finally {
            dirResourceSet.unlockForRead(held);
        }
        Assert.assertTrue("The write lock must be granted once the read lock is released",
                acquired.await(GRANTED_MS, TimeUnit.MILLISECONDS));
        t.join(GRANTED_MS);
    }


    /*
     * The exploit vector. A write is held part way through (which widens the
     * race window that CVE-2024-50379 relies on) while a concurrent
     * getResource() is made for the same path. The read must not be able to
     * observe the partially written file.
     */
    @Test
    public void testGetResourceIsSerialisedWithWrite() throws Exception {
        final String path = "/toctou.jsp";
        final byte[] payload = "<%= \"pwned\" %>".getBytes(StandardCharsets.UTF_8);

        final CountDownLatch writeStarted = new CountDownLatch(1);
        final CountDownLatch releaseWrite = new CountDownLatch(1);
        /*
         * Files.copy() creates the destination file before reading the first
         * byte from the InputStream, so blocking on the first read leaves a
         * zero length file on disk for as long as the stream is blocked.
         */
        InputStream is = new InputStream() {
            private int pos = 0;
            private boolean paused = false;

            @Override
            public int read() throws IOException {
                if (!paused) {
                    paused = true;
                    writeStarted.countDown();
                    try {
                        releaseWrite.await();
                    } catch (InterruptedException e) {
                        throw new IOException(e);
                    }
                }
                if (pos >= payload.length) {
                    return -1;
                }
                return payload[pos++] & 0xFF;
            }
        };

        final AtomicBoolean writeResult = new AtomicBoolean(false);
        Thread writer = new Thread(() -> writeResult.set(dirResourceSet.write(path, is, false)));
        writer.setDaemon(true);

        final CountDownLatch gotResource = new CountDownLatch(1);
        final AtomicBoolean existsSnapshot = new AtomicBoolean(false);
        final AtomicLong lengthSnapshot = new AtomicLong(Long.MIN_VALUE);
        final AtomicReference<byte[]> contentSnapshot = new AtomicReference<>();
        Thread reader = new Thread(() -> {
            WebResource resource = dirResourceSet.getResource(path);
            /*
             * Take the snapshot immediately so that the values recorded are the
             * ones the caller would act on.
             */
            existsSnapshot.set(resource.exists());
            lengthSnapshot.set(resource.getContentLength());
            contentSnapshot.set(resource.getContent());
            gotResource.countDown();
        });
        reader.setDaemon(true);

        try {
            writer.start();
            Assert.assertTrue("Timed out waiting for the write to start",
                    writeStarted.await(GRANTED_MS, TimeUnit.MILLISECONDS));

            reader.start();
            Assert.assertFalse("getResource() must not return while a write for the same path is in progress",
                    gotResource.await(BLOCKED_MS, TimeUnit.MILLISECONDS));
        } finally {
            releaseWrite.countDown();
        }

        Assert.assertTrue("getResource() did not complete once the write finished",
                gotResource.await(GRANTED_MS, TimeUnit.MILLISECONDS));
        writer.join(GRANTED_MS);
        reader.join(GRANTED_MS);

        Assert.assertTrue("The write should have succeeded", writeResult.get());
        // The read must see a fully consistent view of the completed write.
        Assert.assertTrue("The resource should exist", existsSnapshot.get());
        Assert.assertEquals("The resource must not be observed part way through being written",
                payload.length, lengthSnapshot.get());
        Assert.assertArrayEquals(payload, contentSnapshot.get());
    }


    /*
     * The same vector via FileResource.delete(). An in progress read blocks the
     * delete so a reader can never see a resource that is half deleted.
     */
    @Test
    public void testDeleteIsSerialisedWithGetResource() throws Exception {
        final String path = "/delete-me.jsp";
        File file = new File(tempDir, "delete-me.jsp");
        Assert.assertTrue(file.createNewFile());

        WebResource resource = dirResourceSet.getResource(path);
        Assert.assertTrue(resource.exists());

        // Simulate a read of the same path that is still in progress.
        ResourceLock readLock = dirResourceSet.lockForRead(path);

        final CountDownLatch deleted = new CountDownLatch(1);
        final AtomicBoolean deleteResult = new AtomicBoolean(false);
        Thread deleter = new Thread(() -> {
            deleteResult.set(resource.delete());
            deleted.countDown();
        });
        deleter.setDaemon(true);

        try {
            deleter.start();
            Assert.assertFalse("delete() must not proceed while a read for the same path is in progress",
                    deleted.await(BLOCKED_MS, TimeUnit.MILLISECONDS));
            Assert.assertTrue("The file must still be present while the read lock is held", file.exists());
        } finally {
            dirResourceSet.unlockForRead(readLock);
        }

        Assert.assertTrue("delete() did not complete once the read lock was released",
                deleted.await(GRANTED_MS, TimeUnit.MILLISECONDS));
        deleter.join(GRANTED_MS);
        Assert.assertTrue(deleteResult.get());
        Assert.assertFalse(file.exists());
    }


    /*
     * The lock key used by the FileResource created by getResource() has to
     * match the key DirResourceSet uses for the same path, else read and write
     * would use different locks and the race would remain open.
     */
    @Test
    public void testFileResourceUsesSameLockAsResourceSet() throws Exception {
        File file = new File(tempDir, "same-lock.txt");
        Assert.assertTrue(file.createNewFile());
        // Every path element has to exist for the OS to resolve "/sub/..".
        Assert.assertTrue(new File(tempDir, "sub").mkdir());

        // A non-normalized path must still resolve to the shared lock.
        WebResource resource = dirResourceSet.getResource("/sub/../same-lock.txt");
        Assert.assertTrue(resource.exists());

        ResourceLock readLock = dirResourceSet.lockForRead("/same-lock.txt");
        final CountDownLatch deleted = new CountDownLatch(1);
        Thread deleter = new Thread(() -> {
            resource.delete();
            deleted.countDown();
        });
        deleter.setDaemon(true);
        try {
            deleter.start();
            Assert.assertFalse("FileResource.delete() must contend with the ResourceSet lock for the same path",
                    deleted.await(BLOCKED_MS, TimeUnit.MILLISECONDS));
        } finally {
            dirResourceSet.unlockForRead(readLock);
        }
        Assert.assertTrue(deleted.await(GRANTED_MS, TimeUnit.MILLISECONDS));
        deleter.join(GRANTED_MS);
    }


    /*
     * The original 5 argument constructor is retained for compatibility. It
     * creates a FileResource with no associated lock set so delete() must
     * still work.
     */
    @Test
    public void testDeleteWithNoLockSet() throws Exception {
        File file = new File(tempDir, "no-lock-set.txt");
        Assert.assertTrue(file.createNewFile());

        FileResource resource = new FileResource(root, "/no-lock-set.txt", file, false, null);
        Assert.assertTrue(resource.exists());
        Assert.assertTrue(resource.delete());
        Assert.assertFalse(file.exists());
    }


    /* A read only resource is not deleted and no lock is taken. */
    @Test
    public void testDeleteReadOnly() throws Exception {
        File file = new File(tempDir, "read-only.txt");
        Assert.assertTrue(file.createNewFile());

        FileResource resource = new FileResource(root, "/read-only.txt", file, true, null);
        Assert.assertFalse(resource.delete());
        Assert.assertTrue(file.exists());
    }


    /*
     * The case sensitivity DirResourceSet determined for itself in
     * initInternal(). Read via reflection so that the tests assert against the
     * value actually in use rather than re-implementing the detection.
     */
    private static boolean isCaseSensitive(DirResourceSet resourceSet) throws Exception {
        Field field = DirResourceSet.class.getDeclaredField("caseSensitive");
        field.setAccessible(true);
        return ((Boolean) field.get(resourceSet)).booleanValue();
    }


    private static void setCaseSensitive(DirResourceSet resourceSet, boolean caseSensitive) throws Exception {
        Field field = DirResourceSet.class.getDeclaredField("caseSensitive");
        field.setAccessible(true);
        field.set(resourceSet, Boolean.valueOf(caseSensitive));
    }


    private Thread startLockThread(final CountDownLatch acquired, final boolean read, final String path) {
        Thread t = new Thread(() -> {
            if (read) {
                ResourceLock lock = dirResourceSet.lockForRead(path);
                acquired.countDown();
                dirResourceSet.unlockForRead(lock);
            } else {
                ResourceLock lock = dirResourceSet.lockForWrite(path);
                acquired.countDown();
                dirResourceSet.unlockForWrite(lock);
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }
}
