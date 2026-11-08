
package com.deeptrace.extractor;

import java.nio.charset.StandardCharsets;

public final class DNSExtractor {

    private static final int DNS_HEADER_LENGTH = 12;

    public ApplicationMetadata extract(byte[] payload) {

        if (payload == null || payload.length < DNS_HEADER_LENGTH) {
            return null;
        }

        // DNS header fields
        int flags = readUnsignedShort(payload, 2);
        int questionCount = readUnsignedShort(payload, 4);

        // QR bit: 0 = query, 1 = response.
        boolean isResponse = (flags & 0x8000) != 0;

        if (isResponse || questionCount == 0) {
            return null;
        }

        // Only support standard DNS queries (opcode 0).
        int opcode = (flags >> 11) & 0x0F;

        if (opcode != 0) {
            return null;
        }

        // Start reading the first question after the DNS header.
        int position = DNS_HEADER_LENGTH;

        StringBuilder domain = new StringBuilder();

        while (position < payload.length) {

            int labelLength = payload[position] & 0xFF;
            position++;

            // Zero marks the end of the domain name.
            if (labelLength == 0) {
                break;
            }

            // Reject compression pointers and invalid label lengths.
            if ((labelLength & 0xC0) != 0 || labelLength > 63) {
                return null;
            }

            if (position + labelLength > payload.length) {
                return null;
            }

            if (domain.length() > 0) {
                domain.append('.');
            }

            String label = new String(
                    payload,
                    position,
                    labelLength,
                    StandardCharsets.US_ASCII
            );

            domain.append(label);

            position += labelLength;

            if (domain.length() > 253) {
                return null;
            }
        }

        // Ensure that the domain name ended correctly.
        if (position > payload.length || position == DNS_HEADER_LENGTH) {
            return null;
        }

        // QNAME must be followed by QTYPE and QCLASS.
        if (position + 4 > payload.length) {
            return null;
        }

        String extractedDomain = domain.toString();

        if (!isValidDomain(extractedDomain)) {
            return null;
        }

        return new ApplicationMetadata(
                "DNS",
                extractedDomain,
                "Unknown",
                "DNS_QUERY"
        );
    }

    private static int readUnsignedShort(byte[] data, int offset) {

        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private static boolean isValidDomain(String domain) {

        if (domain == null || domain.isBlank() || domain.length() > 253) {
            return false;
        }

        String[] labels = domain.split("\\.", -1);

        for (String label : labels) {

            if (label.isEmpty() || label.length() > 63) {
                return false;
            }

            if (!label.matches(
                    "(?i)^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
            )) {
                return false;
            }
        }

        return true;
    }
}
