
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DNSExtractorTest {

    private final DNSExtractor extractor = new DNSExtractor();

    @Test
    void shouldExtractGoogleDomainFromDnsQuery() {

        byte[] payload = {
                // DNS Header
                0x12, 0x34,             // Transaction ID
                0x01, 0x00,             // Standard query
                0x00, 0x01,             // Questions: 1
                0x00, 0x00,             // Answers: 0
                0x00, 0x00,             // Authority: 0
                0x00, 0x00,             // Additional: 0

                // QNAME: google.com
                0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                0x03, 'c', 'o', 'm',
                0x00,

                // QTYPE: A, QCLASS: IN
                0x00, 0x01,
                0x00, 0x01
        };

        ApplicationMetadata result = extractor.extract(payload);

        assertNotNull(result);
        assertEquals("DNS", result.applicationProtocol());
        assertEquals("google.com", result.domain());
        assertEquals("DNS_QUERY", result.detectionSource());
    }

    @Test
    void shouldRejectDnsResponse() {

        byte[] payload = {
                0x12, 0x34,
                (byte) 0x81, (byte) 0x80,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00
        };

        assertNull(extractor.extract(payload));
    }

    @Test
    void shouldRejectNullPayload() {
        assertNull(extractor.extract(null));
    }

    @Test
    void shouldRejectShortPayload() {
        assertNull(extractor.extract(new byte[]{0x01, 0x02}));
    }
}
