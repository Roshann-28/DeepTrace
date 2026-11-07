package com.deeptrace.reader;

/**
 * Holds one packet record: its PCAP metadata and captured bytes.
 */
public record RawPacket(PcapPacketHeader header, byte[] data) {
    public RawPacket {
        if (header == null || data == null) {
            throw new IllegalArgumentException("Packet header and data cannot be null.");
        }
        if (data.length != header.capturedLength()) {
            throw new IllegalArgumentException("Packet data length does not match captured length.");
        }
    }
}
