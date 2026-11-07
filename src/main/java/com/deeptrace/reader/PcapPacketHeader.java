package com.deeptrace.reader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Represents the 16-byte header that precedes each packet in a classic PCAP file.
 */
public record PcapPacketHeader(
        long timestampSeconds,
        long timestampFraction,
        long capturedLength,
        long originalLength) {

    public static PcapPacketHeader parse(byte[] bytes, ByteOrder byteOrder) {
        if (bytes == null || bytes.length != 16) {
            throw new IllegalArgumentException("A PCAP packet header must contain exactly 16 bytes.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(byteOrder);
        return new PcapPacketHeader(
                Integer.toUnsignedLong(buffer.getInt()),
                Integer.toUnsignedLong(buffer.getInt()),
                Integer.toUnsignedLong(buffer.getInt()),
                Integer.toUnsignedLong(buffer.getInt()));
    }
}
