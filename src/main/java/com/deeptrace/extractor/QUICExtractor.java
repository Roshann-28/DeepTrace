
package com.deeptrace.extractor;

public final class QUICExtractor {

    private static final int QUIC_LONG_HEADER_MASK = 0x80;
    private static final int QUIC_FIXED_BIT_MASK = 0x40;
    private static final int QUIC_PACKET_TYPE_MASK = 0x30;

    // QUIC version identifiers
    private static final long QUIC_VERSION_1 = 0x00000001L;
    private static final long QUIC_VERSION_2 = 0x6B3343CFL;

    // Initial packet type bits
    private static final int QUIC_V1_INITIAL_TYPE = 0x00;
    private static final int QUIC_V2_INITIAL_TYPE = 0x10;

    public boolean isQuicInitial(byte[] payload) {

        if (payload == null || payload.length < 7) {
            return false;
        }

        int firstByte = payload[0] & 0xFF;

        // Check long-header bit.
        if ((firstByte & QUIC_LONG_HEADER_MASK) == 0) {
            return false;
        }

        // Check fixed bit.
        if ((firstByte & QUIC_FIXED_BIT_MASK) == 0) {
            return false;
        }

        long version = readUnsignedInt(payload, 1);

        // Version Negotiation and unsupported versions.
        if (version != QUIC_VERSION_1 &&
                version != QUIC_VERSION_2) {
            return false;
        }

        int packetType = firstByte & QUIC_PACKET_TYPE_MASK;

        if (version == QUIC_VERSION_1) {
            return packetType == QUIC_V1_INITIAL_TYPE;
        }

        return packetType == QUIC_V2_INITIAL_TYPE;
    }

    public long getVersion(byte[] payload) {

        if (payload == null || payload.length < 5) {
            return -1;
        }

        if ((payload[0] & QUIC_LONG_HEADER_MASK) == 0) {
            return -1;
        }

        long version = readUnsignedInt(payload, 1);

        if (version != QUIC_VERSION_1 &&
                version != QUIC_VERSION_2) {
            return -1;
        }

        return version;
    }

    private static long readUnsignedInt(byte[] data, int offset) {

        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (long) (data[offset + 3] & 0xFF);
    }
}
