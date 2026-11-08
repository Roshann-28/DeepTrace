
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class QUICHeaderProtectionTest {

    private final QUICHeaderProtection protection =
            new QUICHeaderProtection();

    private final HexFormat hex = HexFormat.of();

    @Test
    void shouldRemoveQuicV1HeaderProtection() throws Exception {

        byte[] hpKey = hex.parseHex(
                "9f50449e04a0e810283a1e9933adedd2"
        );

        byte[] sample = hex.parseHex(
                "d1b1c98dd7689fb8ec11d242b123dc9b"
        );

        // Original first byte: C3
        // Original packet number: 01 02 03 04
        // Protected using the RFC header protection mask.
        byte[] packet = new byte[21];

        packet[0] = (byte) 0xC0;

        packet[1] = 0x7A;
        packet[2] = (byte) 0x98;
        packet[3] = (byte) 0xEF;
        packet[4] = 0x32;

        System.arraycopy(sample, 0, packet, 5, 16);

        var result = protection.removeHeaderProtection(
                packet,
                1,
                hpKey,
                true
        );

        assertEquals(0xC3, result.firstByte());
        assertEquals(4, result.packetNumberLength());
        assertEquals(0x01020304L, result.packetNumber());

        assertArrayEquals(
                new byte[]{
                        (byte) 0xC3,
                        0x01, 0x02, 0x03, 0x04
                },
                new byte[]{
                        result.packet()[0],
                        result.packet()[1],
                        result.packet()[2],
                        result.packet()[3],
                        result.packet()[4]
                }
        );
    }

    @Test
    void shouldRejectNullPacket() {

        byte[] hpKey = new byte[16];

        assertThrows(
                IllegalArgumentException.class,
                () -> protection.removeHeaderProtection(
                        null, 1, hpKey, true
                )
        );
    }

    @Test
    void shouldRejectInvalidKeyLength() {

        byte[] packet = new byte[21];

        assertThrows(
                IllegalArgumentException.class,
                () -> protection.removeHeaderProtection(
                        packet, 1, new byte[8], true
                )
        );
    }

    @Test
    void shouldRejectInsufficientPacketSample() {

        byte[] packet = new byte[10];

        assertThrows(
                IllegalArgumentException.class,
                () -> protection.removeHeaderProtection(
                        packet, 1, new byte[16], true
                )
        );
    }
}
