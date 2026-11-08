
package com.deeptrace.extractor;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class QUICPacketProcessor {

    private static final long MAX_PACKET_NUMBER = (1L << 62) - 1;
    private static final int AEAD_TAG_LENGTH = 16;

    private final QUICExtractor quicExtractor = new QUICExtractor();
    private final QUICInitialDecryptor initialDecryptor =
            new QUICInitialDecryptor();
    private final QUICHeaderProtection headerProtection =
            new QUICHeaderProtection();
    private final QUICPayloadDecryptor payloadDecryptor =
            new QUICPayloadDecryptor();

    public record ProcessedInitialPacket(
            long version,
            byte[] destinationConnectionId,
            long packetNumber,
            byte[] decryptedPayload
    ) {
        public ProcessedInitialPacket {
            destinationConnectionId = destinationConnectionId.clone();
            decryptedPayload = decryptedPayload.clone();
        }

        @Override
        public byte[] destinationConnectionId() {
            return destinationConnectionId.clone();
        }

        @Override
        public byte[] decryptedPayload() {
            return decryptedPayload.clone();
        }
    }

    public ProcessedInitialPacket process(
            byte[] datagram,
            boolean client,
            long largestReceivedPacketNumber
    ) throws GeneralSecurityException {

        if (datagram == null || datagram.length < 7) {
            throw new IllegalArgumentException("Invalid QUIC datagram.");
        }

        if (largestReceivedPacketNumber < -1
                || largestReceivedPacketNumber > MAX_PACKET_NUMBER) {
            throw new IllegalArgumentException(
                    "Invalid largest received packet number."
            );
        }

        if (!quicExtractor.isQuicInitial(datagram)) {
            throw new IllegalArgumentException(
                    "Datagram is not a supported QUIC Initial packet."
            );
        }

        long version = quicExtractor.getVersion(datagram);

        // Read Destination Connection ID.
        int position = 5;

        int dcidLength = datagram[position++] & 0xFF;

        if (dcidLength < 1 || dcidLength > 20
                || position + dcidLength > datagram.length) {
            throw new IllegalArgumentException(
                    "Invalid Destination Connection ID."
            );
        }

        byte[] dcid = Arrays.copyOfRange(
                datagram, position, position + dcidLength
        );

        position += dcidLength;

        // Skip Source Connection ID.
        if (position >= datagram.length) {
            throw new IllegalArgumentException("Missing Source Connection ID.");
        }

        int scidLength = datagram[position++] & 0xFF;

        if (scidLength > 20
                || position + scidLength > datagram.length) {
            throw new IllegalArgumentException(
                    "Invalid Source Connection ID."
            );
        }

        position += scidLength;

        // Initial packets contain a token-length variable integer.
        VarInt tokenLength = readVarInt(datagram, position);
        position = tokenLength.nextOffset();

        if (tokenLength.value() > datagram.length - position) {
            throw new IllegalArgumentException("Invalid token length.");
        }

        position += (int) tokenLength.value();

        // Read protected packet length.
        VarInt encodedLength = readVarInt(datagram, position);
        position = encodedLength.nextOffset();

        if (encodedLength.value() > datagram.length - position) {
            throw new IllegalArgumentException(
                    "QUIC packet length exceeds datagram boundary."
            );
        }

        int packetNumberOffset = position;
        int packetEnd = position + (int) encodedLength.value();

        // Derive Initial packet protection keys.
        QUICInitialDecryptor.InitialKeys keys =
                initialDecryptor.deriveInitialKeys(
                        dcid,
                        version,
                        client
                );

        if (packetNumberOffset + 4 + 16 > packetEnd) {
            throw new IllegalArgumentException(
                    "QUIC packet is too short for header protection sample."
            );
        }

        // Remove header protection.
        QUICHeaderProtection.UnprotectedHeader header =
                headerProtection.removeHeaderProtection(
                        datagram,
                        packetNumberOffset,
                        keys.headerProtectionKey(),
                        true
                );

        int packetNumberLength = header.packetNumberLength();
        byte[] unprotectedPacket = header.packet();

        if (packetNumberOffset + packetNumberLength > packetEnd) {
            throw new IllegalArgumentException(
                    "Invalid QUIC packet number length."
            );
        }

        // Reconstruct the full packet number.
        long packetNumber = reconstructPacketNumber(
                header.packetNumber(),
                packetNumberLength,
                largestReceivedPacketNumber
        );

        // The unprotected header is authenticated as AAD.
        byte[] associatedData = Arrays.copyOfRange(
                unprotectedPacket,
                0,
                packetNumberOffset + packetNumberLength
        );

        // Ciphertext begins immediately after the packet number.
        byte[] ciphertext = Arrays.copyOfRange(
                unprotectedPacket,
                packetNumberOffset + packetNumberLength,
                packetEnd
        );

        if (ciphertext.length < AEAD_TAG_LENGTH) {
            throw new IllegalArgumentException(
                    "QUIC ciphertext is too short."
            );
        }

        byte[] plaintext = payloadDecryptor.decrypt(
                keys.packetKey(),
                keys.iv(),
                packetNumber,
                associatedData,
                ciphertext
        );

        return new ProcessedInitialPacket(
                version,
                dcid,
                packetNumber,
                plaintext
        );
    }

    private long reconstructPacketNumber(
            long truncatedPacketNumber,
            int packetNumberLength,
            long largestReceivedPacketNumber
    ) {
        int bits = packetNumberLength * 8;

        long window = 1L << bits;
        long halfWindow = window / 2;
        long mask = window - 1;

        long expected = largestReceivedPacketNumber + 1;

        long candidate =
                (expected & ~mask) | truncatedPacketNumber;

        if (candidate <= expected - halfWindow
                && candidate < MAX_PACKET_NUMBER - window + 1) {
            candidate += window;
        } else if (candidate > expected + halfWindow
                && candidate >= window) {
            candidate -= window;
        }

        if (candidate < 0 || candidate > MAX_PACKET_NUMBER) {
            throw new IllegalArgumentException(
                    "Reconstructed packet number is invalid."
            );
        }

        return candidate;
    }

    private record VarInt(long value, int nextOffset) {}

    private VarInt readVarInt(byte[] data, int offset) {

        if (offset >= data.length) {
            throw new IllegalArgumentException(
                    "Unexpected end of QUIC variable integer."
            );
        }

        int firstByte = data[offset] & 0xFF;

        int length = 1 << (firstByte >>> 6);

        if (offset + length > data.length) {
            throw new IllegalArgumentException(
                    "Truncated QUIC variable integer."
            );
        }

        long value = firstByte & 0x3F;

        for (int i = 1; i < length; i++) {
            value = (value << 8) | (data[offset + i] & 0xFFL);
        }

        return new VarInt(value, offset + length);
    }
}
