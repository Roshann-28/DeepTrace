
package com.deeptrace.writer;

import com.deeptrace.reader.PcapGlobalHeader;
import com.deeptrace.reader.PcapPacketHeader;
import com.deeptrace.reader.RawPacket;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

public final class PcapWriter implements Closeable {

    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;

    private final OutputStream output;
    private final PcapGlobalHeader globalHeader;
    private boolean closed;

    public PcapWriter(Path outputPath, PcapGlobalHeader globalHeader)
            throws IOException {

        if (outputPath == null || globalHeader == null) {
            throw new IllegalArgumentException(
                    "Output path and global header cannot be null."
            );
        }

        this.globalHeader = globalHeader;

        this.output = new BufferedOutputStream(
                Files.newOutputStream(outputPath)
        );

        boolean initialized = false;

        try {
            writeGlobalHeader();
            initialized = true;
        } finally {
            if (!initialized) {
                output.close();
            }
        }
    }

    private void writeGlobalHeader() throws IOException {

        ByteOrder order = globalHeader.getByteOrder();

        if (order == null) {
            throw new IllegalArgumentException(
                    "PCAP byte order cannot be null."
            );
        }

        ByteBuffer buffer = ByteBuffer
                .allocate(GLOBAL_HEADER_SIZE)
                .order(order);

        // Write PCAP magic number
        if (globalHeader.isNanoSecondPrecision()) {

            if (order == ByteOrder.LITTLE_ENDIAN) {
                buffer.put(new byte[]{
                        0x4D, 0x3C, (byte) 0xB2, (byte) 0xA1
                });
            } else {
                buffer.put(new byte[]{
                        (byte) 0xA1, (byte) 0xB2, 0x3C, 0x4D
                });
            }

        } else {

            if (order == ByteOrder.LITTLE_ENDIAN) {
                buffer.put(new byte[]{
                        (byte) 0xD4, (byte) 0xC3,
                        (byte) 0xB2, (byte) 0xA1
                });
            } else {
                buffer.put(new byte[]{
                        (byte) 0xA1, (byte) 0xB2,
                        (byte) 0xC3, (byte) 0xD4
                });
            }
        }

        buffer.putShort((short) globalHeader.getMajorVersion());
        buffer.putShort((short) globalHeader.getMinorVersion());
        buffer.putInt((int) globalHeader.getThisZone());
        buffer.putInt((int) globalHeader.getSigFigs());
        buffer.putInt((int) globalHeader.getSnapLength());
        buffer.putInt((int) globalHeader.getLinkType());

        output.write(buffer.array());
    }

    public void writePacket(RawPacket rawPacket) throws IOException {

        if (closed) {
            throw new IOException("PCAP writer is already closed.");
        }

        if (rawPacket == null) {
            throw new IllegalArgumentException(
                    "Raw packet cannot be null."
            );
        }

        PcapPacketHeader header = rawPacket.header();
        byte[] packetData = rawPacket.data();

        validatePacket(header, packetData);

        ByteBuffer buffer = ByteBuffer
                .allocate(PACKET_HEADER_SIZE)
                .order(globalHeader.getByteOrder());

        buffer.putInt((int) header.timestampSeconds());
        buffer.putInt((int) header.timestampFraction());
        buffer.putInt((int) header.capturedLength());
        buffer.putInt((int) header.originalLength());

        // Write packet header first
        output.write(buffer.array());

        // Write actual packet bytes
        output.write(packetData);
    }

    private void validatePacket(
            PcapPacketHeader header,
            byte[] packetData
    ) throws IOException {

        if (header == null || packetData == null) {
            throw new IllegalArgumentException(
                    "Packet header and data cannot be null."
            );
        }

        if (header.timestampSeconds() < 0
                || header.timestampSeconds() > 0xFFFFFFFFL) {
            throw new IOException("Invalid packet timestamp seconds.");
        }

        long maxFraction = globalHeader.isNanoSecondPrecision()
                ? 1_000_000_000L
                : 1_000_000L;

        if (header.timestampFraction() < 0
                || header.timestampFraction() >= maxFraction) {
            throw new IOException("Invalid packet timestamp fraction.");
        }

        if (header.capturedLength() != packetData.length) {
            throw new IOException(
                    "Packet data length does not match captured length."
            );
        }

        if (header.capturedLength() > globalHeader.getSnapLength()) {
            throw new IOException(
                    "Packet exceeds PCAP snapshot length."
            );
        }

        if (header.originalLength() < header.capturedLength()) {
            throw new IOException(
                    "Original length is smaller than captured length."
            );
        }

        if (header.originalLength() > 0xFFFFFFFFL) {
            throw new IOException("Invalid original packet length.");
        }
    }

    @Override
    public void close() throws IOException {

        if (!closed) {
            closed = true;
            output.close();
        }
    }
}
