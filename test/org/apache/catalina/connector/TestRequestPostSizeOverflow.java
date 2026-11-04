/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.connector;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests the size tracking performed for multipart requests.
 * <p>
 * The equivalent size of every non-file part used to be accumulated in a 32-bit
 * counter. Since the size of a part is a 64-bit value, a sufficiently large
 * upload made that counter wrap around to a negative value which then silently
 * passed the <code>maxPostSize</code> check, so the limit could be bypassed.
 * Parts were also published to the application before their size had been
 * validated, which exposed the over sized part even when the limit was
 * enforced.
 */
public class TestRequestPostSizeOverflow extends TomcatBaseTest {

    private static final String CRLF = "\r\n";

    private static final String BOUNDARY = "TomcatMultipartBoundary";

    /**
     * The accumulator used to track the multipart post size must be 64-bit and
     * must refuse to wrap around.
     * <p>
     * A request large enough to wrap a 64-bit accumulator cannot be constructed
     * in a unit test - the counter only grows as bytes are actually received -
     * so the accumulation is exercised here directly against the helper that
     * parseParts() uses for every addition. Note that the result of that helper
     * is assigned straight back into the accumulator, so the code would not
     * compile at all if the accumulator were still an <code>int</code>.
     */
    @Test
    public void testPostSizeAccumulationDoesNotWrap() throws Exception {
        Method helper;
        try {
            helper = Request.class.getDeclaredMethod("addExact", long.class, long.class);
        } catch (NoSuchMethodException nsme) {
            throw new AssertionError("Request does not provide an overflow checked 64-bit helper " +
                    "for accumulating the multipart post size", nsme);
        }
        Assert.assertTrue("The post size helper must be static",
                Modifier.isStatic(helper.getModifiers()));
        Assert.assertEquals("The post size helper must return a long",
                long.class, helper.getReturnType());
        helper.setAccessible(true);

        // Ordinary additions must be unaffected.
        Assert.assertEquals(0, addExact(helper, 0, 0));
        Assert.assertEquals(3, addExact(helper, 1, 2));
        Assert.assertEquals(Long.MAX_VALUE, addExact(helper, Long.MAX_VALUE - 1, 1));

        // Four 1GiB form fields. This is the accumulation that parseParts()
        // performs (name, equals sign, value, separator) and it used to wrap
        // around to a negative value - and so appear to be within the limit -
        // once it passed 2GiB.
        final long fieldSize = 1024 * 1024 * 1024;
        final long maxPostSize = 2 * 1024 * 1024;
        long postSize = 0;
        for (int i = 0; i < 4; i++) {
            // Name
            postSize = addExact(helper, postSize, 2);
            // Equals sign
            postSize = addExact(helper, postSize, 1);
            // Value length
            postSize = addExact(helper, postSize, fieldSize);
            // Value separator
            postSize = addExact(helper, postSize, 1);
            Assert.assertTrue("Post size wrapped around to " + postSize, postSize > 0);
        }
        Assert.assertEquals(4 * (fieldSize + 4), postSize);
        Assert.assertTrue("The post size limit was not seen to be exceeded", postSize > maxPostSize);

        // Where the accumulation genuinely cannot be represented it has to fail
        // rather than wrap.
        try {
            addExact(helper, Long.MAX_VALUE, 1);
            Assert.fail("Overflowing the post size did not throw an ArithmeticException");
        } catch (ArithmeticException expected) {
            // Expected
        }
        try {
            addExact(helper, Long.MIN_VALUE, -1);
            Assert.fail("Underflowing the post size did not throw an ArithmeticException");
        } catch (ArithmeticException expected) {
            // Expected
        }
    }

    /**
     * A part that on its own exceeds maxPostSize must not be published to the
     * application.
     */
    @Test
    public void testOverSizedPartIsNotExposed() throws Exception {
        // The equivalent size of the part is 2 (name) + 1 + 64 (value) + 1
        String body = doMultipartRequest(30, new int[] { 64 });

        Assert.assertTrue(body, body.contains("getParts=IllegalStateException"));
        Assert.assertEquals(body, "published=0", getPublished(body));
    }

    /**
     * Where an earlier part is within maxPostSize that part may be published,
     * but the part that exceeds the limit must not be.
     */
    @Test
    public void testOnlyPartsWithinTheLimitAreExposed() throws Exception {
        // The equivalent sizes are 2 + 1 + 4 + 1 == 8 and 2 + 1 + 64 + 1 == 68
        String body = doMultipartRequest(30, new int[] { 4, 64 });

        Assert.assertTrue(body, body.contains("getParts=IllegalStateException"));
        Assert.assertEquals(body, "published=1", getPublished(body));
    }

    /**
     * Parts within maxPostSize must still be visible to the application once
     * they have been validated.
     */
    @Test
    public void testPartsWithinTheLimitAreExposed() throws Exception {
        String body = doMultipartRequest(1000, new int[] { 4, 8 });

        Assert.assertTrue(body, body.contains("getParts=2"));
        Assert.assertEquals(body, "published=2", getPublished(body));
    }

    private String doMultipartRequest(int maxPostSize, int[] valueLengths) throws Exception {
        Tomcat tomcat = getTomcatInstance();

        Context ctx = tomcat.addContext("", TEMP_DIR);
        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet());
        // No FileUpload level limits so that it is the connector's maxPostSize
        // that trips. The threshold keeps the parts in memory.
        w.setMultipartConfigElement(new MultipartConfigElement("", -1, -1, 1024 * 1024));
        ctx.addServletMappingDecoded("/parts", "parts");

        tomcat.getConnector().setMaxPostSize(maxPostSize);
        tomcat.start();

        Map<String,List<String>> reqHead = new HashMap<>();
        reqHead.put("Content-Type",
                Collections.singletonList("multipart/form-data; boundary=" + BOUNDARY));

        ByteChunk out = new ByteChunk();
        int rc = postUrl(buildBody(valueLengths), "http://localhost:" + getPort() + "/parts", out,
                reqHead, null);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        return out.toString();
    }

    private static String getPublished(String body) {
        for (String line : body.split("\n")) {
            if (line.trim().startsWith("published=")) {
                return line.trim();
            }
        }
        return "published=<not reported>";
    }

    private static byte[] buildBody(int[] valueLengths) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < valueLengths.length; i++) {
            sb.append("--").append(BOUNDARY).append(CRLF);
            // A two byte part name and no file name so that the part counts
            // towards the post size.
            sb.append("Content-Disposition: form-data; name=\"p").append(i).append('\"');
            sb.append(CRLF).append(CRLF);
            for (int j = 0; j < valueLengths[i]; j++) {
                sb.append('x');
            }
            sb.append(CRLF);
        }
        sb.append("--").append(BOUNDARY).append("--").append(CRLF);

        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static long addExact(Method helper, long x, long y) throws Exception {
        try {
            return ((Long) helper.invoke(null, Long.valueOf(x), Long.valueOf(y))).longValue();
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw ite;
        }
    }

    private static class PartsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");

            PrintWriter out = resp.getWriter();

            try {
                out.println("getParts=" + req.getParts().size());
            } catch (IllegalStateException ise) {
                out.println("getParts=IllegalStateException");
            }

            // The parts that parseParts() published on the internal request. An
            // over sized part must never appear here, whether or not the
            // application goes on to call getParts().
            Collection<Part> published = ((RequestFacade) req).request.parts;
            out.println("published=" +
                    (published == null ? "null" : Integer.toString(published.size())));
        }
    }
}
