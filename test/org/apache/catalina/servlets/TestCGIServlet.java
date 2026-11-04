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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Locale;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.ExpandWar;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * The CGI servlet used to locate the requested script by walking the file
 * system directly - {@code new File(webAppRootDir)} followed by
 * {@code File.isFile()}. The file system, not the web application's resources,
 * therefore decided which script a URL mapped to. Where the file system maps
 * more than one name to the same file - a case insensitive file system being the
 * most common example - a request for one name executed the script stored under
 * another name. Any security constraint defined for the {@code pathInfo}
 * component of the URL could then be bypassed simply by varying the name used in
 * the request.
 * <p>
 * The scripts are now located via {@link WebResourceRoot} which compares the
 * requested path with the canonical path of the file it resolves to and refuses
 * to return a resource when the two differ. That check is what makes the lookup
 * case sensitive on a case insensitive file system.
 * <p>
 * These tests emulate that class of file system aliasing on a case sensitive
 * file system by adding a symbolic link whose name differs from the name of the
 * script it points to only by case. {@code File.isFile()} follows the link (so
 * the original implementation found and executed the script) whereas the
 * canonical path check in the resources implementation rejects it.
 */
public class TestCGIServlet extends TomcatBaseTest {

    private static final String SCRIPT_FILE = "test.sh";
    /* Differs from SCRIPT_FILE by case only. */
    private static final String ALIAS_NAME = "TEST.sh";

    private static final String CGI_PATH_PREFIX = "WEB-INF/cgi";
    private static final String CGI_MARKER = "CGI-EXECUTED";

    private static final String SCRIPT =
            "#!/bin/sh" + "\n" +
            "echo \"Content-Type: text/plain\"" + "\n" +
            "echo \"\"" + "\n" +
            "echo \"" + CGI_MARKER + "\"" + "\n" +
            "echo \"SCRIPT_NAME=[$SCRIPT_NAME]\"" + "\n" +
            "echo \"PATH_INFO=[$PATH_INFO]\"" + "\n";

    private File tempDocBase;
    private File cgiDir;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        tempDocBase = Files.createTempDirectory(getTemporaryDirectory().toPath(), "cgi").toFile();
        cgiDir = new File(tempDocBase, CGI_PATH_PREFIX);
        Assert.assertTrue(cgiDir.mkdirs());
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
     * A request that differs from the name of the script on disk by case only
     * must not execute that script. On a case insensitive file system the
     * original implementation executed it, bypassing any security constraint
     * defined for the correctly cased path.
     */
    @Test
    public void testCaseMismatchedScriptIsNotExecuted() throws Exception {
        createScript(cgiDir, SCRIPT_FILE);
        createCaseOnlyAlias(cgiDir, ALIAS_NAME, SCRIPT_FILE);

        startCgiServlet();

        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/" + ALIAS_NAME,
                responseBody, null);

        Assert.assertEquals("The CGI servlet executed [" + SCRIPT_FILE +
                "] for a request for [" + ALIAS_NAME + "]. Response body was [" +
                toString(responseBody) + "]", 404, rc);
        Assert.assertFalse(toString(responseBody).contains(CGI_MARKER));
    }


    /*
     * The same for a script in a sub-directory of the CGI location, i.e. where
     * the aliased name is not the final path segment. It is the pathInfo
     * component of the URL that security constraints are defined against so an
     * alias part way along the path is just as exploitable.
     */
    @Test
    public void testCaseMismatchedDirectoryIsNotExecuted() throws Exception {
        File subDir = new File(cgiDir, "sub");
        Assert.assertTrue(subDir.mkdir());
        createScript(subDir, SCRIPT_FILE);
        createCaseOnlyAlias(cgiDir, "SUB", "sub");

        startCgiServlet();

        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/SUB/" + SCRIPT_FILE,
                responseBody, null);

        Assert.assertEquals("The CGI servlet executed [sub/" + SCRIPT_FILE +
                "] for a request for [SUB/" + SCRIPT_FILE + "]. Response body was [" +
                toString(responseBody) + "]", 404, rc);
        Assert.assertFalse(toString(responseBody).contains(CGI_MARKER));
    }


    /*
     * Confirms the pre-condition for the tests above: the file system does
     * resolve the aliased name to the script (so the original, file system based
     * lookup found it) while the web application resources do not.
     */
    @Test
    public void testResourcesRejectTheCaseMismatchedPath() throws Exception {
        createScript(cgiDir, SCRIPT_FILE);
        createCaseOnlyAlias(cgiDir, ALIAS_NAME, SCRIPT_FILE);

        Context ctxt = startCgiServlet();
        WebResourceRoot resources = ctxt.getResources();

        // The lookup the original implementation performed
        Assert.assertTrue(new File(cgiDir, ALIAS_NAME).isFile());

        // The lookup the fixed implementation performs
        Assert.assertTrue(resources.getResource("/" + CGI_PATH_PREFIX + "/" + SCRIPT_FILE).isFile());
        Assert.assertFalse(resources.getResource("/" + CGI_PATH_PREFIX + "/" + ALIAS_NAME).isFile());
    }


    /*
     * The correctly cased path must still be executed.
     */
    @Test
    public void testScriptIsExecuted() throws Exception {
        createScript(cgiDir, SCRIPT_FILE);
        createCaseOnlyAlias(cgiDir, ALIAS_NAME, SCRIPT_FILE);

        startCgiServlet();

        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/" + SCRIPT_FILE,
                responseBody, null);

        String body = toString(responseBody);
        Assert.assertEquals(body, 200, rc);
        Assert.assertTrue(body, body.contains(CGI_MARKER));
        Assert.assertTrue(body, body.contains("SCRIPT_NAME=[/cgi-bin/" + SCRIPT_FILE + "]"));
        Assert.assertTrue(body, body.contains("PATH_INFO=[]"));
    }


    /*
     * A script in a sub-directory of the CGI location must still be executed
     * and the trailing path must still be reported as PATH_INFO. This exercises
     * the multiple iterations of the resource look-up loop, including the
     * directory that has to be skipped before the script is found.
     */
    @Test
    public void testScriptInSubDirectoryIsExecuted() throws Exception {
        File subDir = new File(cgiDir, "sub");
        Assert.assertTrue(subDir.mkdir());
        createScript(subDir, SCRIPT_FILE);

        startCgiServlet();

        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/sub/" + SCRIPT_FILE +
                "/extra/path", responseBody, null);

        String body = toString(responseBody);
        Assert.assertEquals(body, 200, rc);
        Assert.assertTrue(body, body.contains(CGI_MARKER));
        Assert.assertTrue(body, body.contains("SCRIPT_NAME=[/cgi-bin/sub/" + SCRIPT_FILE + "]"));
        Assert.assertTrue(body, body.contains("PATH_INFO=[/extra/path]"));
    }


    /*
     * A directory must never be treated as a script. The look-up has to skip it
     * and keep walking the remaining path segments.
     */
    @Test
    public void testDirectoryIsNotExecuted() throws Exception {
        File subDir = new File(cgiDir, "sub");
        Assert.assertTrue(subDir.mkdir());
        createScript(subDir, SCRIPT_FILE);

        startCgiServlet();

        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/sub", responseBody, null);

        Assert.assertEquals(toString(responseBody), 404, rc);
    }


    private Context startCgiServlet() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        Context ctxt = tomcat.addContext("", tempDocBase.getAbsolutePath());
        // The CGI servlet is a restricted servlet
        ctxt.setPrivileged(true);

        Wrapper w = Tomcat.addServlet(ctxt, "cgi", CGIServlet.class.getName());
        w.addInitParameter("cgiPathPrefix", CGI_PATH_PREFIX);
        w.addInitParameter("executable", "/bin/sh");
        w.setLoadOnStartup(1);
        ctxt.addServletMappingDecoded("/cgi-bin/*", "cgi");

        tomcat.start();

        // The scripts are created before the context starts but caching is
        // disabled so that any resource look-up in a test sees the file system
        // as it is when the request is made.
        ctxt.getResources().setCachingAllowed(false);

        return ctxt;
    }


    private static void createScript(File dir, String name) throws IOException {
        File script = new File(dir, name);
        Files.write(script.toPath(), SCRIPT.getBytes(StandardCharsets.ISO_8859_1));
        Assert.assertTrue(script.isFile());
    }


    /*
     * Creates a second name for an existing file (or directory) that differs
     * from the original name by case only. This is what a case insensitive file
     * system provides for free and what the original implementation followed.
     * Tests that depend on it are skipped where symbolic links are not
     * available.
     */
    private static void createCaseOnlyAlias(File dir, String alias, String target) {
        Assert.assertEquals(alias.toLowerCase(Locale.ENGLISH), target.toLowerCase(Locale.ENGLISH));
        try {
            Files.createSymbolicLink(Paths.get(dir.getAbsolutePath(), alias), Paths.get(target));
        } catch (IOException | UnsupportedOperationException e) {
            Assume.assumeNoException("Symbolic links are not available", e);
        }
        Assume.assumeTrue("The file system did not resolve [" + alias + "] to [" + target + "]",
                new File(dir, alias).exists());
    }


    private static String toString(ByteChunk bc) {
        return new String(bc.getBytes(), bc.getStart(), bc.getLength(), StandardCharsets.ISO_8859_1);
    }
}
