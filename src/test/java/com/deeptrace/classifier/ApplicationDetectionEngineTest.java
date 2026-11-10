
package com.deeptrace.classifier;

import com.deeptrace.extractor.ApplicationMetadata;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class ApplicationDetectionEngineTest {

    private final ApplicationDetectionEngine engine =
            new ApplicationDetectionEngine();

    @Test
    void shouldDetectYouTubeFromHttpHost() {

        String request =
                "GET /watch HTTP/1.1\r\n" +
                        "Host: www.youtube.com\r\n" +
                        "User-Agent: DeepTrace\r\n" +
                        "\r\n";

        byte[] payload =
                request.getBytes(StandardCharsets.US_ASCII);

        ApplicationDetectionEngine.DetectionResult result =
                engine.detect(payload);

        assertTrue(result.isIdentified());
        assertEquals(AppType.YOUTUBE, result.applicationType());

        assertNotNull(result.metadata());

        assertEquals("www.youtube.com", result.metadata().domain());

        assertEquals("HTTP", result.metadata().applicationProtocol());
    }

    @Test
    void shouldDetectGoogleFromDnsQuery() {

        byte[] payload = createDnsQuery("www.google.com");

        ApplicationDetectionEngine.DetectionResult result =
                engine.detect(payload);

        assertTrue(result.isIdentified());
        assertEquals(AppType.GOOGLE, result.applicationType());

        assertNotNull(result.metadata());
        assertEquals("www.google.com", result.metadata().domain());
        assertEquals("DNS", result.metadata().applicationProtocol());
    }

    @Test
    void shouldDetectQuicInitialPacket() {

        byte[] packet = new byte[7];

        // QUIC v1 Initial packet header.
        packet[0] = (byte) 0xC0;

        // Version 1.
        packet[1] = 0x00;
        packet[2] = 0x00;
        packet[3] = 0x00;
        packet[4] = 0x01;

        // DCID length = 1.
        packet[5] = 0x01;

        // DCID.
        packet[6] = 0x11;

        ApplicationDetectionEngine.DetectionResult result =
                engine.detect(packet);

        assertTrue(result.isIdentified());
        assertEquals(AppType.QUIC, result.applicationType());

        assertNotNull(result.metadata());
        assertEquals("QUIC", result.metadata().applicationProtocol());
        assertEquals("QUIC_INITIAL", result.metadata().detectionSource());
    }

    @Test
    void shouldReturnUnknownForUnrecognizedPayload() {

        byte[] payload = {
                0x01, 0x02, 0x03, 0x04
        };

        ApplicationDetectionEngine.DetectionResult result =
                engine.detect(payload);

        assertFalse(result.isIdentified());
        assertEquals(AppType.UNKNOWN, result.applicationType());
        assertNull(result.metadata());
    }

    @Test
    void shouldHandleNullPayload() {

        ApplicationDetectionEngine.DetectionResult result =
                engine.detect(null);

        assertFalse(result.isIdentified());
        assertEquals(AppType.UNKNOWN, result.applicationType());
        assertNull(result.metadata());
    }

    private byte[] createDnsQuery(String domain) {

        byte[] domainBytes =
                domain.getBytes(StandardCharsets.US_ASCII);

        int labelCount = domain.split("\\.").length;

        byte[] payload = new byte[
                12 + domainBytes.length + labelCount + 1 + 4
                ];

        // Transaction ID.
        payload[0] = 0x12;
        payload[1] = 0x34;

        // Standard query.
        payload[2] = 0x01;
        payload[3] = 0x00;

        // One question.
        payload[4] = 0x00;
        payload[5] = 0x01;

        int position = 12;

        for (String label : domain.split("\\.")) {

            byte[] labelBytes =
                    label.getBytes(StandardCharsets.US_ASCII);

            payload[position++] = (byte) labelBytes.length;

            System.arraycopy(
                    labelBytes,
                    0,
                    payload,
                    position,
                    labelBytes.length
            );

            position += labelBytes.length;
        }

        // End of domain name.
        payload[position++] = 0x00;

        // QTYPE = A (IPv4).
        payload[position++] = 0x00;
        payload[position++] = 0x01;

        // QCLASS = IN.
        payload[position++] = 0x00;
        payload[position] = 0x01;

        return payload;
    }
}
