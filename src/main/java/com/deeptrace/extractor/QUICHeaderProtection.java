
package com.deeptrace.extractor;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public final class QUICHeaderProtection {

    private static final int SAMPLE_LENGTH = 16;
    private static final int MASK_LENGTH = 5;

    public record UnprotectedHeader(
            byte[] packet,
            int firstByte,
            int packetNumberLength,
            long packetNumber
    ) {
        public UnprotectedHeader {
            packet = packet.clone();
        }

        @Override
        public byte[] packet() {
            return packet.clone();
        }
    }

    public UnprotectedHeader removeHeaderProtection(
            byte[] protectedPacket,
            int packetNumberOffset,
            byte[] headerProtectionKey,
            boolean longHeader
    ) throws GeneralSecurityException {

        if (protectedPacket == null) {
            throw new IllegalArgumentException("Packet cannot be null.");
        }

        if (headerProtectionKey == null || headerProtectionKey.length != 16) {
            throw new IllegalArgumentException(
                    "AES-128 header protection key must be 16 bytes."
            );
        }

        if (packetNumberOffset < 1 ||
                packetNumberOffset + 4 + SAMPLE_LENGTH > protectedPacket.length) {
            throw new IllegalArgumentException(
                    "Packet is too short for header protection removal."
            );
        }

        byte[] packet = protectedPacket.clone();

        // The sample always starts four bytes after the packet number offset.
        byte[] sample = new byte[SAMPLE_LENGTH];

        System.arraycopy(
                packet,
                packetNumberOffset + 4,
                sample,
                0,
                SAMPLE_LENGTH
        );

        byte[] mask = generateMask(headerProtectionKey, sample);

        // Long headers protect only the lower four bits.
        // Short headers protect the lower five bits.
        int firstByteMask = longHeader ? 0x0F : 0x1F;

        packet[0] = (byte) (
                (packet[0] & 0xFF) ^ (mask[0] & firstByteMask)
        );

        int firstByte = packet[0] & 0xFF;

        int packetNumberLength = (firstByte & 0x03) + 1;

        long packetNumber = 0;

        for (int i = 0; i < packetNumberLength; i++) {

            int index = packetNumberOffset + i;

            packet[index] = (byte) (
                    (packet[index] & 0xFF) ^ (mask[i + 1] & 0xFF)
            );

            packetNumber = (packetNumber << 8)
                    | (packet[index] & 0xFFL);
        }

        return new UnprotectedHeader(
                packet,
                firstByte,
                packetNumberLength,
                packetNumber
        );
    }

    private byte[] generateMask(
            byte[] headerProtectionKey,
            byte[] sample
    ) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        SecretKeySpec key = new SecretKeySpec(
                headerProtectionKey,
                "AES"
        );

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedSample = cipher.doFinal(sample);

        byte[] mask = new byte[MASK_LENGTH];

        System.arraycopy(
                encryptedSample,
                0,
                mask,
                0,
                MASK_LENGTH
        );

        return mask;
    }
}
