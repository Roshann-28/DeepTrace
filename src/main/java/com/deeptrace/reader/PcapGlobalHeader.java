package com.deeptrace.reader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Represents the 24-byte global header of a classic PCAP file.
 */
public final class PcapGlobalHeader {
    private final int majorVersion;
    private final int minorVersion;
    private final long thisZone;
    private final long sigFigs;
    private final long snapLength;
    private final long linkType;
    private final ByteOrder byteOrder;
    private final boolean nanoSecondPrecision;

    private PcapGlobalHeader(
            int majorVersion,
            int minorVersion,
            long thisZone,
            long sigFigs,
            long snapLength,
            long linkType,
            ByteOrder byteOrder,
            boolean nanoSecondPrecision) {
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.thisZone = thisZone;
        this.sigFigs = sigFigs;
        this.snapLength = snapLength;
        this.linkType = linkType;
        this.byteOrder = byteOrder;
        this.nanoSecondPrecision = nanoSecondPrecision;
    }

    public static PcapGlobalHeader parse(byte[] headerBytes) {
        if (headerBytes == null || headerBytes.length != 24) {
            throw new IllegalArgumentException("A PCAP global header must contain exactly 24 bytes.");
        }

        ByteOrder order;
        boolean nanoPrecision;

        // The first four bytes identify byte order and timestamp precision.
        if (matches(headerBytes, 0xD4, 0xC3, 0xB2, 0xA1)) {
            order = ByteOrder.LITTLE_ENDIAN;
            nanoPrecision = false;
        } else if (matches(headerBytes, 0xA1, 0xB2, 0xC3, 0xD4)) {
            order = ByteOrder.BIG_ENDIAN;
            nanoPrecision = false;
        } else if (matches(headerBytes, 0x4D, 0x3C, 0xB2, 0xA1)) {
            order = ByteOrder.LITTLE_ENDIAN;
            nanoPrecision = true;
        } else if (matches(headerBytes, 0xA1, 0xB2, 0x3C, 0x4D)) {
            order = ByteOrder.BIG_ENDIAN;
            nanoPrecision = true;
        } else {
            throw new IllegalArgumentException("Unsupported or invalid PCAP magic number.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(headerBytes).order(order);
        buffer.position(4);

        int major = Short.toUnsignedInt(buffer.getShort());
        int minor = Short.toUnsignedInt(buffer.getShort());
        long thisZone = buffer.getInt();
        long sigFigs = Integer.toUnsignedLong(buffer.getInt());
        long snapLength = Integer.toUnsignedLong(buffer.getInt());
        long linkType = Integer.toUnsignedLong(buffer.getInt());

        if (major != 2 || minor != 4) {
            throw new IllegalArgumentException(
                    "Unsupported PCAP version: " + major + "." + minor + " (expected 2.4).");
        }
        if (snapLength == 0) {
            throw new IllegalArgumentException("PCAP snapshot length cannot be zero.");
        }

        return new PcapGlobalHeader(
                major, minor, thisZone, sigFigs, snapLength, linkType, order, nanoPrecision);
    }

    private static boolean matches(byte[] bytes, int b0, int b1, int b2, int b3) {
        return (bytes[0] & 0xFF) == b0
                && (bytes[1] & 0xFF) == b1
                && (bytes[2] & 0xFF) == b2
                && (bytes[3] & 0xFF) == b3;
    }

    public int getMajorVersion() { return majorVersion; }
    public int getMinorVersion() { return minorVersion; }
    public long getThisZone() { return thisZone; }
    public long getSigFigs() { return sigFigs; }
    public long getSnapLength() { return snapLength; }
    public long getLinkType() { return linkType; }
    public ByteOrder getByteOrder() { return byteOrder; }
    public boolean isNanoSecondPrecision() { return nanoSecondPrecision; }

    @Override
    public String toString() {
        return "PCAP " + majorVersion + "." + minorVersion
                + ", byteOrder=" + byteOrder
                + ", timestampPrecision=" + (nanoSecondPrecision ? "nanoseconds" : "microseconds")
                + ", snapLength=" + snapLength
                + ", linkType=" + linkType;
    }
}
