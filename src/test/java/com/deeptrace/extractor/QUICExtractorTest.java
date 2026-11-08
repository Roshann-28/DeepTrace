
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class QUICExtractorTest {

    private final QUICExtractor extractor = new QUICExtractor();

    @Test
    void shouldRecognizeQuicV1InitialPacket() {

        byte[] payload = {
                (byte) 0xC0, // Long header, fixed bit, Initial type
                0x00, 0x00, 0x00, 0x01, // QUIC v1
                0x08, // DCID length
                0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08
        };

        assertTrue(extractor.isQuicInitial(payload));
        assertEquals(1L, extractor.getVersion(payload));
    }

    @Test
    void shouldRecognizeQuicV2InitialPacket() {

        byte[] payload = {
                (byte) 0xD0, // Long header, fixed bit, v2 Initial type
                0x6B, 0x33, 0x43, (byte) 0xCF,
                0x04,
                0x01, 0x02, 0x03, 0x04
        };

        assertTrue(extractor.isQuicInitial(payload));
        assertEquals(0x6B3343CFL, extractor.getVersion(payload));
    }

    @Test
    void shouldRejectShortHeaderPacket() {

        byte[] payload = {
                0x40, 0x01, 0x02, 0x03, 0x04
        };

        assertFalse(extractor.isQuicInitial(payload));
    }

    @Test
    void shouldRejectUnsupportedVersion() {

        byte[] payload = {
                (byte) 0xC0,
                0x00, 0x00, 0x00, 0x02,
                0x04, 0x01, 0x02, 0x03, 0x04
        };

        assertFalse(extractor.isQuicInitial(payload));
        assertEquals(-1L, extractor.getVersion(payload));
    }

    @Test
    void shouldRejectNullPayload() {

        assertFalse(extractor.isQuicInitial(null));
        assertEquals(-1L, extractor.getVersion(null));
    }
}
