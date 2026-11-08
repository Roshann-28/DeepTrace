
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class QUICPacketProcessorTest {

    private final QUICPacketProcessor processor =
            new QUICPacketProcessor();

    // ==========================================
    // NEGATIVE TESTS
    // ==========================================

    @Test
    void shouldRejectNullDatagram() {

        assertThrows(
                IllegalArgumentException.class,
                () -> processor.process(null, true, -1)
        );
    }

    @Test
    void shouldRejectShortDatagram() {

        byte[] packet = new byte[5];

        assertThrows(
                IllegalArgumentException.class,
                () -> processor.process(packet, true, -1)
        );
    }

    @Test
    void shouldRejectInvalidLargestPacketNumber() {

        byte[] packet = new byte[7];

        assertThrows(
                IllegalArgumentException.class,
                () -> processor.process(packet, true, -2)
        );
    }

    @Test
    void shouldRejectUnsupportedQuicPacket() {

        byte[] packet = new byte[20];

        assertThrows(
                IllegalArgumentException.class,
                () -> processor.process(packet, true, -1)
        );
    }

    @Test
    void shouldRejectInvalidDestinationConnectionId() {

        byte[] packet = new byte[7];

        // QUIC v1 Initial packet header.
        packet[0] = (byte) 0xC0;

        // Version 1.
        packet[1] = 0x00;
        packet[2] = 0x00;
        packet[3] = 0x00;
        packet[4] = 0x01;

        // Invalid DCID length: zero.
        packet[5] = 0x00;

        assertThrows(
                IllegalArgumentException.class,
                () -> processor.process(packet, true, -1)
        );
    }

    @Test
    void shouldRejectMissingSourceConnectionId() {

        byte[] packet = new byte[7];

        packet[0] = (byte) 0xC0;

        // QUIC v1.
        packet[1] = 0x00;
        packet[2] = 0x00;
        packet[3] = 0x00;
        packet[4] = 0x01;

        // DCID length = 1.
        packet[5] = 0x01;

        // One DCID byte.
        packet[6] = 0x11;

        assertThrows(
                IllegalArgumentException.class,
                () -> processor.process(packet, true, -1)
        );
    }

    // ==========================================
    // POSITIVE TEST
    // ==========================================

    @Test
    void shouldSuccessfullyDecryptQuicInitialPacket()
            throws Exception {

        QUICInitialDecryptor keyDeriver =
                new QUICInitialDecryptor();

        byte[] dcid = HexFormat.of().parseHex(
                "8394c8f03e515708"
        );

        byte[] expectedPayload = new byte[]{
                0x01, 0x02, 0x03
        };

        // Derive client Initial keys.
        QUICInitialDecryptor.InitialKeys keys =
                keyDeriver.deriveInitialKeys(
                        dcid,
                        0x00000001L,
                        true
                );

        // Generate a protected QUIC Initial packet.
        byte[] packet = createProtectedInitialPacket(
                dcid,
                keys,
                expectedPayload
        );

        // Process the protected packet.
        QUICPacketProcessor.ProcessedInitialPacket result =
                processor.process(
                        packet,
                        true,
                        -1
                );

        // Verify QUIC version.
        assertEquals(
                0x00000001L,
                result.version()
        );

        // Verify Destination Connection ID.
        assertArrayEquals(
                dcid,
                result.destinationConnectionId()
        );

        // Verify reconstructed packet number.
        assertEquals(
                0,
                result.packetNumber()
        );

        // Verify decrypted payload.
        assertArrayEquals(
                expectedPayload,
                result.decryptedPayload()
        );
    }

    // ==========================================
    // TEST PACKET GENERATOR
    // ==========================================

    private byte[] createProtectedInitialPacket(
            byte[] dcid,
            QUICInitialDecryptor.InitialKeys keys,
            byte[] plaintext
    ) throws Exception {

        long packetNumber = 0;

        // Construct an unprotected QUIC Initial header.
        byte[] header = new byte[
                5 + 1 + dcid.length + 1 + 1 + 1 + 1
                ];

        int position = 0;

        // First byte: QUIC v1 Initial.
        header[position++] = (byte) 0xC0;

        // Version 1.
        header[position++] = 0x00;
        header[position++] = 0x00;
        header[position++] = 0x00;
        header[position++] = 0x01;

        // Destination Connection ID length.
        header[position++] = (byte) dcid.length;

        // Destination Connection ID.
        System.arraycopy(
                dcid,
                0,
                header,
                position,
                dcid.length
        );

        position += dcid.length;

        // Source Connection ID length = 0.
        header[position++] = 0x00;

        // Token length = 0.
        header[position++] = 0x00;

        // Packet length:
        // 1 byte packet number + ciphertext + 16-byte tag.
        header[position++] = (byte) (
                1 + plaintext.length + 16
        );

        // Remember packet number offset.
        int packetNumberOffset = position;

        // Packet number = 0.
        header[position++] = 0x00;

        // Complete unprotected header is authenticated data.
        byte[] associatedData = Arrays.copyOf(
                header,
                position
        );

        // ======================================
        // CREATE PACKET NONCE
        // ======================================

        byte[] nonce = keys.iv();

        for (int i = 0; i < Long.BYTES; i++) {

            nonce[nonce.length - 1 - i] ^= (byte)
                    (packetNumber >>> (i * 8));
        }

        // ======================================
        // AES-GCM ENCRYPTION
        // ======================================

        Cipher gcm = Cipher.getInstance(
                "AES/GCM/NoPadding"
        );

        gcm.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(
                        keys.packetKey(),
                        "AES"
                ),
                new GCMParameterSpec(128, nonce)
        );

        gcm.updateAAD(associatedData);

        byte[] ciphertext = gcm.doFinal(plaintext);

        // Combine header and encrypted payload.
        byte[] packet = Arrays.copyOf(
                associatedData,
                associatedData.length + ciphertext.length
        );

        System.arraycopy(
                ciphertext,
                0,
                packet,
                associatedData.length,
                ciphertext.length
        );

        // ======================================
        // QUIC HEADER PROTECTION
        // ======================================

        // Header protection sample starts four bytes
        // after the packet number offset.
        byte[] sample = Arrays.copyOfRange(
                packet,
                packetNumberOffset + 4,
                packetNumberOffset + 4 + 16
        );

        Cipher hp = Cipher.getInstance(
                "AES/ECB/NoPadding"
        );

        hp.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(
                        keys.headerProtectionKey(),
                        "AES"
                )
        );

        byte[] mask = hp.doFinal(sample);

        // Protect first byte of the header.
        packet[0] ^= (byte) (mask[0] & 0x0F);

        // Protect packet number.
        packet[packetNumberOffset] ^= mask[1];

        return packet;
    }
}
