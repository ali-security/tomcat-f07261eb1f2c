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
package org.apache.catalina.servlets;

import java.io.File;
import java.io.FilenameFilter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import javax.servlet.ServletContext;

import org.junit.Assert;
import org.junit.Test;

import static org.apache.catalina.startup.SimpleHttpClient.CRLF;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.ExpandWar;
import org.apache.catalina.startup.SimpleHttpClient;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * The original implementation of partial PUT used a temporary file in the
 * ServletContext temporary directory whose name was derived from the request
 * URI with the path separator replaced by '.'. The name was therefore
 * predictable and, because the file was only removed via
 * {@link File#deleteOnExit()}, it also outlived the request.
 * <p>
 * That allowed a client to plant a file with a name of its choosing (and with
 * content of its choosing) in the ServletContext temporary directory - which is
 * also the default storage location for Tomcat's file based session persistence
 * - and it allowed two different, but '.' equivalent, request URIs to share the
 * same temporary file so content could leak from one partial PUT into another.
 * <p>
 * These tests confirm that a partial PUT no longer uses a name that the client
 * can predict and that the temporary file is removed once the request
 * completes.
 */
public class TestDefaultServletPartialPut extends TomcatBaseTest {

    private static final String START_TEXT = "Starting text";
    private static final String START_LEN = Integer.toString(START_TEXT.length());
    private static final String PATCH_TEXT = "Ending *";
    private static final String PATCH_LEN = Integer.toString(PATCH_TEXT.length());
    private static final String END_TEXT = "Ending * text";

    /* The prefix used by the fixed implementation. */
    private static final String TEMP_FILE_PREFIX = "put-part-";

    private File tempDocBase;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        tempDocBase = Files.createTempDirectory(getTemporaryDirectory().toPath(), "put").toFile();
    }


    @Override
    public void tearDown() throws Exception {
        try {
            super.tearDown();
        } finally {
            ExpandWar.deleteDir(tempDocBase, false);
        }
    }


    /*
     * A partial PUT must not create a file in the ServletContext temporary
     * directory at a location that the client can predict from the request URI
     * and must not leave the temporary file behind once the request completes.
     */
    @Test
    public void testPartialPutTempFileIsNotPredictable() throws Exception {
        Context ctxt = startWritableDefaultServlet();
        File tempDir = getContextTempDir(ctxt);

        File subDir = new File(tempDocBase, "dir");
        Assert.assertTrue(subDir.mkdir());

        String target = "/dir/test.txt";

        PutClient putClient = new PutClient(getPort());

        // Full PUT to create the resource
        putClient.connect();
        putClient.setRequest(new String[] {
                "PUT " + target + " HTTP/1.1" + CRLF +
                "Host: localhost:" + getPort() + CRLF +
                "Content-Length: " + START_LEN + CRLF +
                CRLF +
                START_TEXT
        });
        putClient.processRequest(false);
        Assert.assertTrue(putClient.getResponseLine(), putClient.isResponse201());
        putClient.disconnect();
        putClient.reset();

        // Partial PUT
        putClient.connect();
        putClient.setRequest(new String[] {
                "PUT " + target + " HTTP/1.1" + CRLF +
                "Host: localhost:" + getPort() + CRLF +
                "Content-Range: bytes=0-" + PATCH_LEN + "/" + START_LEN + CRLF +
                "Content-Length: " + PATCH_LEN + CRLF +
                CRLF +
                PATCH_TEXT
        });
        putClient.processRequest(false);
        Assert.assertTrue(putClient.getResponseLine(), putClient.isResponse204());
        putClient.disconnect();

        // The name the original implementation used
        File predictable = new File(tempDir, target.replace('/', '.'));
        Assert.assertFalse("Partial PUT created a temporary file with the predictable name [" +
                predictable.getName() + "] in the ServletContext temporary directory",
                predictable.exists());

        // Nothing at all should be left behind
        Assert.assertEquals("Partial PUT left a temporary file behind",
                0, listTempFiles(tempDir).length);

        // The partial PUT must still have done its job
        Assert.assertEquals(END_TEXT, getResource(target));
    }


    /*
     * The ServletContext temporary directory is the default storage location
     * for Tomcat's file based session persistence and FileStore reads
     * '<session-id>.session' from it. A partial PUT must not allow a client to
     * create a file with such a name. Note the temporary file was created
     * before, and independently of, the write to the web application so the
     * original implementation planted the file even when - as here - the PUT
     * itself could not be completed.
     */
    @Test
    public void testPartialPutCannotPlantSessionFile() throws Exception {
        Context ctxt = startWritableDefaultServlet();
        File tempDir = getContextTempDir(ctxt);

        // Deliberately not created in the doc base so the PUT cannot succeed
        String target = "/sessions/DEADBEEF.session";
        String payload = "serialized-session-payload";
        String payloadLen = Integer.toString(payload.length());

        PutClient putClient = new PutClient(getPort());
        putClient.connect();
        putClient.setRequest(new String[] {
                "PUT " + target + " HTTP/1.1" + CRLF +
                "Host: localhost:" + getPort() + CRLF +
                "Content-Range: bytes=0-" + (payload.length() - 1) + "/" + payloadLen + CRLF +
                "Content-Length: " + payloadLen + CRLF +
                CRLF +
                payload
        });
        putClient.processRequest(false);
        // The web application resource could not be written
        Assert.assertTrue(putClient.getResponseLine(),
                putClient.responseLineStartsWith("HTTP/1.1 409 "));
        putClient.disconnect();

        File planted = new File(tempDir, target.replace('/', '.'));
        Assert.assertFalse("Partial PUT planted [" + planted.getName() +
                "] in the ServletContext temporary directory", planted.exists());

        String[] sessionFiles = tempDir.list(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(".session");
            }
        });
        Assert.assertNotNull(sessionFiles);
        Assert.assertEquals("Partial PUT created a file that FileStore would load as a session",
                0, sessionFiles.length);

        Assert.assertEquals("Partial PUT left a temporary file behind",
                0, listTempFiles(tempDir).length);
    }


    /*
     * Replacing '/' with '.' meant that two different request URIs could map to
     * the same temporary file. Because the temporary file was reused rather than
     * recreated, content from one partial PUT leaked into the resource written
     * by another.
     */
    @Test
    public void testPartialPutTempFileIsNotSharedByEquivalentPaths() throws Exception {
        Context ctxt = startWritableDefaultServlet();
        File tempDir = getContextTempDir(ctxt);

        File subDir = new File(tempDocBase, "a");
        Assert.assertTrue(subDir.mkdir());

        // '/a.b.txt' and '/a/b.txt' both convert to '.a.b.txt'
        String attackerTarget = "/a.b.txt";
        String victimTarget = "/a/b.txt";

        String attackerText = "EVILEVILEVILEVIL";
        String victimStartText = "AB";
        String victimPatchText = "GOOD";
        // The total length is longer than the existing resource so the bytes
        // between the two are read from the temporary file
        int totalLen = attackerText.length();

        PutClient putClient = new PutClient(getPort());

        // Attacker primes the shared temporary file
        putClient.connect();
        putClient.setRequest(new String[] {
                "PUT " + attackerTarget + " HTTP/1.1" + CRLF +
                "Host: localhost:" + getPort() + CRLF +
                "Content-Range: bytes=0-" + (totalLen - 1) + "/" + totalLen + CRLF +
                "Content-Length: " + attackerText.length() + CRLF +
                CRLF +
                attackerText
        });
        putClient.processRequest(false);
        Assert.assertTrue(putClient.getResponseLine(), putClient.isResponse201());
        putClient.disconnect();
        putClient.reset();

        // Victim creates its own resource
        putClient.connect();
        putClient.setRequest(new String[] {
                "PUT " + victimTarget + " HTTP/1.1" + CRLF +
                "Host: localhost:" + getPort() + CRLF +
                "Content-Length: " + victimStartText.length() + CRLF +
                CRLF +
                victimStartText
        });
        putClient.processRequest(false);
        Assert.assertTrue(putClient.getResponseLine(), putClient.isResponse201());
        putClient.disconnect();
        putClient.reset();

        // Victim appends to it with a partial PUT
        putClient.connect();
        putClient.setRequest(new String[] {
                "PUT " + victimTarget + " HTTP/1.1" + CRLF +
                "Host: localhost:" + getPort() + CRLF +
                "Content-Range: bytes=" + (totalLen - victimPatchText.length()) + "-" +
                        (totalLen - 1) + "/" + totalLen + CRLF +
                "Content-Length: " + victimPatchText.length() + CRLF +
                CRLF +
                victimPatchText
        });
        putClient.processRequest(false);
        Assert.assertTrue(putClient.getResponseLine(), putClient.isResponse204());
        putClient.disconnect();

        String victimContent = getResource(victimTarget);

        Assert.assertFalse("Content from a partial PUT to [" + attackerTarget +
                "] leaked into the resource written by a partial PUT to [" + victimTarget +
                "]. Resource content was [" + victimContent + "]",
                victimContent.contains(attackerText.substring(0, 4)));

        // The victim's own partial PUT must still have worked as expected. The
        // content of the bytes the victim did not supply is not asserted
        // because RandomAccessFile.setLength() explicitly leaves the content of
        // the extended portion of the file undefined. The requirement that
        // matters is that they do not contain another request's content and
        // that is checked above.
        Assert.assertEquals(totalLen, victimContent.length());
        Assert.assertTrue(victimContent, victimContent.startsWith(victimStartText));
        Assert.assertTrue(victimContent, victimContent.endsWith(victimPatchText));

        Assert.assertEquals("Partial PUT left a temporary file behind",
                0, listTempFiles(tempDir).length);
    }


    private Context startWritableDefaultServlet() throws Exception {
        // Configure a web app with a read/write default servlet
        Tomcat tomcat = getTomcatInstance();
        Context ctxt = tomcat.addContext("", tempDocBase.getAbsolutePath());

        Wrapper w = Tomcat.addServlet(ctxt, "default", DefaultServlet.class.getName());
        w.addInitParameter("readonly", "false");
        w.addInitParameter("allowPartialPut", "true");
        ctxt.addServletMappingDecoded("/", "default");

        tomcat.start();

        // Disable caching so the results of the PUTs are visible immediately
        ctxt.getResources().setCachingAllowed(false);

        return ctxt;
    }


    private static File getContextTempDir(Context ctxt) {
        File tempDir = (File) ctxt.getServletContext().getAttribute(ServletContext.TEMPDIR);
        Assert.assertNotNull(tempDir);
        Assert.assertTrue(tempDir.isDirectory());
        return tempDir;
    }


    private static String[] listTempFiles(File tempDir) {
        String[] result = tempDir.list(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.startsWith(TEMP_FILE_PREFIX);
            }
        });
        Assert.assertNotNull(result);
        return result;
    }


    private String getResource(String target) throws Exception {
        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + target, responseBody, null);
        Assert.assertEquals(200, rc);
        return new String(responseBody.getBytes(), responseBody.getStart(),
                responseBody.getLength(), StandardCharsets.ISO_8859_1);
    }


    private static class PutClient extends SimpleHttpClient {

        PutClient(int port) {
            setPort(port);
        }


        @Override
        public boolean isResponseBodyOK() {
            return false;
        }
    }
}
