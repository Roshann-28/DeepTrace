
package com.deeptrace.extractor;

import java.nio.charset.StandardCharsets;

public final class TLSExtractor {

    private static final int TLS_HANDSHAKE_RECORD = 0x16;
    private static final int CLIENT_HELLO = 0x01;
    private static final int SERVER_NAME_EXTENSION = 0x0000;

    public ApplicationMetadata extract(byte[] payload) {

        if (payload == null || payload.length < 9) {
            return null;
        }

        // Check TLS record type.
        if ((payload[0] & 0xFF) != TLS_HANDSHAKE_RECORD) {
            return null;
        }

        // Check handshake type.
        if ((payload[5] & 0xFF) != CLIENT_HELLO) {
            return null;
        }

        int recordLength = readUnsignedShort(payload, 3);

        if (recordLength + 5 > payload.length) {
            return null;
        }

        int position = 9;

        // ClientHello version + random.
        position += 2 + 32;

        if (position >= payload.length) {
            return null;
        }

        // Session ID.
        int sessionIdLength = payload[position] & 0xFF;
        position += 1 + sessionIdLength;

        if (position + 2 > payload.length) {
            return null;
        }

        // Cipher suites.
        int cipherSuitesLength = readUnsignedShort(payload, position);
        position += 2 + cipherSuitesLength;

        if (position >= payload.length) {
            return null;
        }

        // Compression methods.
        int compressionLength = payload[position] & 0xFF;
        position += 1 + compressionLength;

        if (position + 2 > payload.length) {
            return null;
        }

        // Extensions length.
        int extensionsLength = readUnsignedShort(payload, position);
        position += 2;

        int extensionsEnd = position + extensionsLength;

        if (extensionsEnd > payload.length) {
            return null;
        }

        // Iterate through TLS extensions.
        while (position + 4 <= extensionsEnd) {

            int extensionType = readUnsignedShort(payload, position);
            int extensionLength = readUnsignedShort(payload, position + 2);

            position += 4;

            if (position + extensionLength > extensionsEnd) {
                return null;
            }

            if (extensionType == SERVER_NAME_EXTENSION) {

                return extractServerName(
                        payload,
                        position,
                        extensionLength
                );
            }

            position += extensionLength;
        }

        return null;
    }

    private ApplicationMetadata extractServerName(
            byte[] payload,
            int offset,
            int length
    ) {

        int end = offset + length;

        if (length < 5 || end > payload.length) {
            return null;
        }

        // Server name list length.
        int listLength = readUnsignedShort(payload, offset);
        int position = offset + 2;

        if (listLength != length - 2) {
            return null;
        }

        while (position + 3 <= end) {

            int nameType = payload[position] & 0xFF;
            int nameLength = readUnsignedShort(payload, position + 1);

            position += 3;

            if (position + nameLength > end) {
                return null;
            }

            if (nameType == 0 && nameLength > 0) {

                String domain = new String(
                        payload,
                        position,
                        nameLength,
                        StandardCharsets.US_ASCII
                );

                if (!isValidDomain(domain)) {
                    return null;
                }

                return new ApplicationMetadata(
                        "TLS",
                        domain,
                        "Unknown",
                        "TLS_SNI"
                );
            }

            position += nameLength;
        }

        return null;
    }

    private static int readUnsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private static boolean isValidDomain(String domain) {

        if (domain.isBlank() || domain.length() > 253) {
            return false;
        }

        return domain.matches(
                "(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$"
        );
    }
}
