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
package org.apache.coyote.http2;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.Adapter;
import org.apache.coyote.Request;
import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.net.SocketWrapperBase;

/**
 * Tests for the counting of active (remote) HTTP/2 streams (CVE-2024-34750).
 * <p>
 * A stream must be added to, and removed from, the count of active streams no
 * more than once and must be removed once it is no longer active. If the count
 * is not maintained correctly it never returns to zero which means the keep
 * alive timeout is never applied to the connection (an infinite timeout is used
 * instead) and the connection is never closed.
 */
public class TestHttp2ActiveStreamCount extends Http2TestBase {

    private static final AtomicReference<Http2UpgradeHandler> HANDLER = new AtomicReference<>();


    /*
     * A stream that is reset by the client while it is still active is removed
     * from the active stream count by the reset. When the response for that
     * stream subsequently completes, the end of stream processing attempts to
     * remove the same stream from the active stream count a second time. That
     * second removal must be a NO-OP.
     */
    @Test
    public void testStreamRemovedFromActiveCountOnceOnly() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        Stream stream = new Stream(Integer.valueOf(3), handler);

        // Client sends HEADERS with the end of stream flag set
        stream.receivedStartOfHeaders(false);
        stream.incrementActiveRemoteStreamCount();
        Assert.assertEquals(1, handler.activeRemoteStreamCount.get());
        stream.receivedEndOfStream();
        // Stream is half closed (remote) so it is still active
        Assert.assertTrue(stream.isActive());

        // Client resets the stream while the response is still being written.
        // This mirrors what Http2UpgradeHandler.reset() does for a stream that
        // is still active when the RST_STREAM frame is received.
        stream.receiveReset(Http2Error.CANCEL.getCode());
        Assert.assertFalse(stream.isActive());
        handler.decrementActiveRemoteStreamCount(stream);
        Assert.assertEquals(0, handler.activeRemoteStreamCount.get());

        // The response then completes. Prior to the fix for CVE-2024-34750
        // this removed the stream from the active stream count a second time
        // leaving the count negative. Since the count then never returned to
        // zero an infinite timeout was used for the connection and the
        // connection was never closed.
        handler.sentEndOfStream(stream);
        Assert.assertEquals("Stream removed from the active stream count more than once",
                0, handler.activeRemoteStreamCount.get());

        // Any further attempts must also be NO-OPs
        handler.decrementActiveRemoteStreamCount(stream);
        handler.sentEndOfStream(stream);
        Assert.assertEquals("Stream removed from the active stream count more than once",
                0, handler.activeRemoteStreamCount.get());
    }


    /*
     * A response that completes normally must remove the stream from the count
     * of active streams exactly once. This covers the end of stream being
     * signalled on a DATA frame and on a HEADERS frame (response with no body).
     */
    @Test
    public void testSentEndOfStreamRemovesStreamFromActiveCountOnceOnly() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        Stream stream = new Stream(Integer.valueOf(3), handler);

        stream.receivedStartOfHeaders(false);
        stream.incrementActiveRemoteStreamCount();
        stream.receivedEndOfStream();
        Assert.assertEquals(1, handler.activeRemoteStreamCount.get());
        Assert.assertTrue(stream.isActive());

        handler.sentEndOfStream(stream);
        Assert.assertFalse(stream.isActive());
        Assert.assertEquals("Stream not removed from the active stream count once complete",
                0, handler.activeRemoteStreamCount.get());

        handler.sentEndOfStream(stream);
        Assert.assertEquals("Stream removed from the active stream count more than once",
                0, handler.activeRemoteStreamCount.get());
    }


    /*
     * A stream that was never added to the active stream count (e.g. a stream
     * created by a PRIORITY frame that never receives a HEADERS frame) must
     * never be removed from it.
     */
    @Test
    public void testStreamNotRemovedFromActiveCountIfNeverAdded() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        Stream stream = new Stream(Integer.valueOf(3), handler);

        handler.decrementActiveRemoteStreamCount(stream);
        Assert.assertEquals("Stream removed from the active stream count without being added",
                0, handler.activeRemoteStreamCount.get());
    }


    /*
     * A stream must only be added to the active stream count once no matter how
     * many HEADERS frames (e.g. request headers followed by trailer fields) it
     * receives.
     */
    @Test
    public void testStreamAddedToActiveCountOnceOnly() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        Stream stream = new Stream(Integer.valueOf(3), handler);

        stream.incrementActiveRemoteStreamCount();
        stream.incrementActiveRemoteStreamCount();
        stream.incrementActiveRemoteStreamCount();
        Assert.assertEquals("Stream added to the active stream count more than once",
                1, handler.activeRemoteStreamCount.get());

        handler.decrementActiveRemoteStreamCount(stream);
        Assert.assertEquals(0, handler.activeRemoteStreamCount.get());
    }


    /*
     * End to end test. A stream that is reset by the server because the request
     * headers exceed the configured limits must be removed from the count of
     * active streams. Note that the stream is added to that count as soon as
     * the HEADERS frame starts to be processed - before the point at which the
     * limits are found to have been exceeded.
     */
    @Test
    public void testStreamResetByServerReturnsActiveStreamCountToZero() throws Exception {
        HANDLER.set(null);

        enableTesterHttp2();
        // Ensure the request below exceeds the header count limit
        http2Protocol.setMaxHeaderCount(10);
        configureAndStartWebApplication();
        openClientConnection();
        doHttpUpgrade();
        sendClientPreface();
        validateHttp2InitialResponse();

        Http2UpgradeHandler handler = HANDLER.get();
        Assert.assertNotNull("Failed to obtain the connection's upgrade handler", handler);
        awaitActiveStreamCount(handler, 0);

        // Too many headers. The server resets the stream.
        sendGetRequestWithCustomHeaders(3, 20, 32);

        parser.readFrame(true);
        Assert.assertEquals("3-RST-[" + Http2Error.ENHANCE_YOUR_CALM.getCode() + "]\n",
                output.getTrace());
        output.clearTrace();

        awaitActiveStreamCount(handler, 0);

        // The connection must still be usable
        sendSimpleGetRequest(5);
        readSimpleGetResponse();
        Assert.assertEquals(getSimpleResponseTrace(5), output.getTrace());
        output.clearTrace();

        awaitActiveStreamCount(handler, 0);
    }


    /*
     * End to end test. A stream that is reset by the client while the response
     * is still being written is removed from the count of active streams by the
     * reset. The subsequent completion of the (aborted) response must not
     * remove the same stream from that count a second time - if it does the
     * count never returns to zero, an infinite timeout is used for the
     * connection and the connection is never closed.
     */
    @Test
    public void testClientResetWhileActiveReturnsActiveStreamCountToZero() throws Exception {
        HANDLER.set(null);

        enableTesterHttp2();
        configureAndStartWebApplication();
        openClientConnection();
        doHttpUpgrade();
        sendClientPreface();
        validateHttp2InitialResponse();

        Http2UpgradeHandler handler = HANDLER.get();
        Assert.assertNotNull("Failed to obtain the connection's upgrade handler", handler);
        awaitActiveStreamCount(handler, 0);

        // A response that is larger than the connection flow control window so
        // the server is still writing it when the reset arrives.
        sendLargeGetRequest(3);
        // Read the response headers. The stream is now active on the server.
        parser.readFrame(true);
        output.clearTrace();
        awaitActiveStreamCount(handler, 1);

        sendRst(3, Http2Error.CANCEL.getCode());

        // The reset removes the stream from the count of active streams
        awaitActiveStreamCount(handler, 0);

        // Allow the server to finish processing the reset stream. The count
        // must remain at zero rather than dropping below it.
        Thread.sleep(1000);
        Assert.assertEquals("Stream removed from the active stream count more than once",
                0, handler.activeRemoteStreamCount.get());
    }


    /*
     * End to end test. Request trailer fields are sent in a second HEADERS
     * frame on an existing stream. That second HEADERS frame must not add the
     * stream to the count of active streams a second time.
     */
    @Test
    public void testRequestTrailersReturnActiveStreamCountToZero() throws Exception {
        HANDLER.set(null);

        enableTesterHttp2();
        http2Protocol.setAllowedTrailerHeaders(TRAILER_HEADER_NAME);
        Http2UpgradeHandler handler = startAndConnect();

        byte[] headersFrameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        byte[] dataFrameHeader = new byte[9];
        ByteBuffer dataPayload = ByteBuffer.allocate(256);
        byte[] trailerFrameHeader = new byte[9];
        ByteBuffer trailerPayload = ByteBuffer.allocate(256);

        buildPostRequest(headersFrameHeader, headersPayload, false, dataFrameHeader, dataPayload,
                null, trailerFrameHeader, trailerPayload, 3);

        writeFrame(headersFrameHeader, headersPayload);
        writeFrame(dataFrameHeader, dataPayload);
        writeFrame(trailerFrameHeader, trailerPayload);

        readFramesUntil("3-EndOfStream\n");

        awaitActiveStreamCount(handler, 0);
    }


    /*
     * End to end test. A request with trailer fields that exceed the configured
     * limits is reset by the server. The stream must be counted once (not once
     * per HEADERS frame) and must be removed from the count by the reset.
     */
    @Test
    public void testExcessiveRequestTrailersReturnActiveStreamCountToZero() throws Exception {
        HANDLER.set(null);

        enableTesterHttp2();
        http2Protocol.setAllowedTrailerHeaders(TRAILER_HEADER_NAME);
        http2Protocol.setMaxTrailerCount(0);
        Http2UpgradeHandler handler = startAndConnect();

        byte[] headersFrameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        byte[] dataFrameHeader = new byte[9];
        ByteBuffer dataPayload = ByteBuffer.allocate(256);
        byte[] trailerFrameHeader = new byte[9];
        ByteBuffer trailerPayload = ByteBuffer.allocate(256);

        buildPostRequest(headersFrameHeader, headersPayload, false, dataFrameHeader, dataPayload,
                null, trailerFrameHeader, trailerPayload, 3);

        writeFrame(headersFrameHeader, headersPayload);
        writeFrame(dataFrameHeader, dataPayload);
        writeFrame(trailerFrameHeader, trailerPayload);

        readFramesUntil("3-RST-[" + Http2Error.ENHANCE_YOUR_CALM.getCode() + "]\n");

        awaitActiveStreamCount(handler, 0);
    }


    /*
     * End to end test. A response with trailer fields ends the stream with a
     * HEADERS frame rather than a DATA frame. Sending that HEADERS frame must
     * remove the stream from the count of active streams.
     */
    @Test
    public void testResponseTrailersReturnActiveStreamCountToZero() throws Exception {
        HANDLER.set(null);

        enableTesterHttp2();
        Http2UpgradeHandler handler = startAndConnect();

        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        buildGetRequest(frameHeader, headersPayload, null, 3, "/responseTrailers");
        writeFrame(frameHeader, headersPayload);

        readFramesUntil("3-EndOfStream\n");

        awaitActiveStreamCount(handler, 0);
    }


    /*
     * End to end test. The application completes the response without reading
     * the request body so the server resets the stream to tell the client to
     * stop sending the body. That reset must remove the stream from the count
     * of active streams.
     */
    @Test
    public void testUnreadRequestBodyReturnsActiveStreamCountToZero() throws Exception {
        HANDLER.set(null);

        enableTesterHttp2();
        Http2UpgradeHandler handler = startAndConnect();

        byte[] headersFrameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        byte[] dataFrameHeader = new byte[9];
        ByteBuffer dataPayload = ByteBuffer.allocate(128);

        // Request body is declared but never sent
        buildPostRequest(headersFrameHeader, headersPayload, false, null, 1024, "/noRead",
                dataFrameHeader, dataPayload, null, null, null, 3);
        writeFrame(headersFrameHeader, headersPayload);

        readFramesUntil("3-RST-[" + Http2Error.CANCEL.getCode() + "]\n");

        awaitActiveStreamCount(handler, 0);
    }


    /*
     * End to end test of the consequence of mis-counting active streams. Once
     * the stream that was reset by the server (because the request headers
     * exceeded the configured limits) has been removed from the count of
     * active streams, there are no active streams so the keep-alive timeout
     * must be used for the connection. If the stream is not removed from the
     * count, an infinite timeout is used and the connection is never closed.
     */
    @Test
    public void testKeepAliveTimeoutAppliedAfterServerReset() throws Exception {
        HANDLER.set(null);

        enableTesterHttp2();
        http2Protocol.setMaxHeaderCount(10);
        Http2UpgradeHandler handler = startAndConnect();

        // Too many headers. The server resets the stream.
        sendGetRequestWithCustomHeaders(3, 20, 32);

        parser.readFrame(true);
        Assert.assertEquals("3-RST-[" + Http2Error.ENHANCE_YOUR_CALM.getCode() + "]\n",
                output.getTrace());
        output.clearTrace();

        awaitActiveStreamCount(handler, 0);
        awaitKeepAliveTimeout(handler);
    }


    private Http2UpgradeHandler startAndConnect() throws Exception {
        configureAndStartTesterWebApplication();
        openClientConnection();
        doHttpUpgrade();
        sendClientPreface();
        validateHttp2InitialResponse();

        Http2UpgradeHandler handler = HANDLER.get();
        Assert.assertNotNull("Failed to obtain the connection's upgrade handler", handler);
        awaitActiveStreamCount(handler, 0);
        return handler;
    }


    private void configureAndStartTesterWebApplication() throws LifecycleException {
        Tomcat tomcat = getTomcatInstance();

        Context ctxt = tomcat.addContext("", null);
        Tomcat.addServlet(ctxt, "simple", new SimpleServlet());
        ctxt.addServletMappingDecoded("/simple", "simple");
        Tomcat.addServlet(ctxt, "noRead", new NoReadServlet());
        ctxt.addServletMappingDecoded("/noRead", "noRead");
        Tomcat.addServlet(ctxt, "responseTrailers", new ResponseTrailersServlet());
        ctxt.addServletMappingDecoded("/responseTrailers", "responseTrailers");

        tomcat.start();
    }


    /*
     * Read frames until the expected frame is seen. The number of frames read
     * is bounded so a missing frame triggers a test failure rather than a
     * hang.
     */
    private void readFramesUntil(String expected) throws Exception {
        for (int i = 0; i < 20 && !output.getTrace().contains(expected); i++) {
            parser.readFrame(true);
        }
        Assert.assertTrue(output.getTrace(), output.getTrace().contains(expected));
        output.clearTrace();
    }


    /*
     * When there are no active streams the connection must use the keep-alive
     * timeout rather than an infinite timeout (represented by -1). The timeout
     * is updated by the thread processing the connection which is not the
     * thread running this test so allow a little time for it to be set.
     */
    private static void awaitKeepAliveTimeout(Http2UpgradeHandler handler) throws Exception {
        long connectionTimeout = getConnectionTimeout(handler);
        long endTime = System.currentTimeMillis() + 10000;
        while (connectionTimeout == -1 && System.currentTimeMillis() < endTime) {
            Thread.sleep(20);
            connectionTimeout = getConnectionTimeout(handler);
        }
        Assert.assertNotEquals("An infinite timeout is being used for a connection with no active streams",
                -1, connectionTimeout);
    }


    private static long getConnectionTimeout(Http2UpgradeHandler handler) throws Exception {
        Field field = Http2UpgradeHandler.class.getDeclaredField("connectionTimeout");
        field.setAccessible(true);
        return field.getLong(handler);
    }


    /*
     * The count of active streams is updated by the thread processing the
     * stream which is not the thread running this test so allow a little time
     * for the expected value to be reached.
     */
    private static void awaitActiveStreamCount(Http2UpgradeHandler handler, int expected)
            throws InterruptedException {
        int count = handler.activeRemoteStreamCount.get();
        long endTime = System.currentTimeMillis() + 10000;
        while (count != expected && System.currentTimeMillis() < endTime) {
            Thread.sleep(20);
            count = handler.activeRemoteStreamCount.get();
        }
        Assert.assertEquals("Unexpected count of active streams", expected, count);
    }


    private void sendGetRequestWithCustomHeaders(int streamId, int headerCount, int headerSize)
            throws Exception {
        StringBuilder headerValue = new StringBuilder(headerSize);
        for (int i = 0; i < headerSize; i++) {
            headerValue.append('a');
        }
        String v = headerValue.toString();

        MimeHeaders headers = new MimeHeaders();
        headers.addValue(":method").setString("GET");
        headers.addValue(":scheme").setString("http");
        headers.addValue(":path").setString("/simple");
        headers.addValue(":authority").setString("localhost:" + getPort());
        for (int i = 0; i < headerCount; i++) {
            headers.addValue("x-tomcattest" + i).setString(v);
        }

        ByteBuffer headersPayload = ByteBuffer.allocate(8 * 1024);
        HpackEncoder.State state = hpackEncoder.encode(headers, headersPayload);
        Assert.assertEquals(HpackEncoder.State.COMPLETE, state);
        headersPayload.flip();

        byte[] frameHeader = new byte[9];
        ByteUtil.setThreeBytes(frameHeader, 0, headersPayload.limit());
        frameHeader[3] = FrameType.HEADERS.getIdByte();
        // Flags. end of headers (0x04) and end of stream (0x01)
        frameHeader[4] = 0x05;
        ByteUtil.set31Bits(frameHeader, 5, streamId);

        writeFrame(frameHeader, headersPayload);
    }


    /*
     * As per Http2TestBase.enableHttp2() but using an upgrade protocol that
     * exposes the Http2UpgradeHandler created for the connection.
     */
    private void enableTesterHttp2() {
        Tomcat tomcat = getTomcatInstance();
        Connector connector = tomcat.getConnector();
        http2Protocol = new TesterHttp2Protocol();
        http2Protocol.setReadTimeout(10000);
        http2Protocol.setWriteTimeout(10000);
        http2Protocol.setKeepAliveTimeout(25000);
        http2Protocol.setStreamReadTimeout(5000);
        http2Protocol.setStreamWriteTimeout(5000);
        http2Protocol.setMaxConcurrentStreams(200);
        connector.addUpgradeProtocol(http2Protocol);
    }


    private static class TesterHttp2Protocol extends Http2Protocol {

        @Override
        public String getHttpUpgradeName(boolean isSSLEnabled) {
            return "h2c";
        }

        @Override
        public InternalHttpUpgradeHandler getInternalUpgradeHandler(
                SocketWrapperBase<?> socketWrapper, Adapter adapter, Request coyoteRequest) {
            Http2UpgradeHandler handler;
            if (socketWrapper.hasAsyncIO()) {
                handler = new Http2AsyncUpgradeHandler(this, adapter, coyoteRequest);
            } else {
                handler = new Http2UpgradeHandler(this, adapter, coyoteRequest);
            }
            HANDLER.set(handler);
            return handler;
        }
    }


    /*
     * Completes the response without reading the request body.
     */
    private static class NoReadServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print("OK");
        }
    }


    /*
     * Generates a response with trailer fields so the end of stream is sent on
     * a HEADERS frame.
     */
    private static class ResponseTrailersServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setTrailerFields(() -> Collections.singletonMap("x-trailer", "trailer-value"));
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print("OK");
        }
    }
}
