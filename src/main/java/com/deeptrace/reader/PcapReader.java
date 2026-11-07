package com.deeptrace.reader;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads classic PCAP files sequentially.
 *
 * nextPacket() returns null only when the end of the file is reached cleanly.
 */
public final class PcapReader implements Closeable {
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;
    private static final long MAX_PACKET_ALLOCATION = 64L * 1024 * 1024;

    private final InputStream input;
    private final PcapGlobalHeader globalHeader;
    private long packetCount;

    public PcapReader(Path filePath) throws IOException {
        if (filePath == null) {
            throw new IllegalArgumentException("Input file path cannot be null.");
        }

        this.input = Files.newInputStream(filePath);
        boolean initialized = false;

        try {
            byte[] bytes = readExactly(input, GLOBAL_HEADER_SIZE, false);
            this.globalHeader = PcapGlobalHeader.parse(bytes);
            initialized = true;
        } finally {
            if (!initialized) {
                input.close();
            }
        }
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public long getPacketCount() {
        return packetCount;
    }

    /**
     * Reads the next packet. Returns null when no more packet records remain.
     */
    public RawPacket nextPacket() throws IOException {
        byte[] packetHeaderBytes = readExactly(input, PACKET_HEADER_SIZE, true);
        if (packetHeaderBytes == null) {
            return null;
        }

        PcapPacketHeader packetHeader =
                PcapPacketHeader.parse(packetHeaderBytes, globalHeader.getByteOrder());

        long capturedLength = packetHeader.capturedLength();

        if (capturedLength > globalHeader.getSnapLength()) {
            throw new IOException("Packet captured length (" + capturedLength
                    + ") exceeds PCAP snapshot length (" + globalHeader.getSnapLength() + ").");
        }
        if (capturedLength > MAX_PACKET_ALLOCATION) {
            throw new IOException("Packet is too large to safely allocate: " + capturedLength + " bytes.");
        }
        if (packetHeader.originalLength() < capturedLength) {
            throw new IOException("Original packet length is smaller than captured packet length.");
        }

        byte[] packetData = readExactly(input, (int) capturedLength, false);
        packetCount++;
        return new RawPacket(packetHeader, packetData);
    }

    private static byte[] readExactly(InputStream input, int length, boolean allowCleanEof)
            throws IOException {
        byte[] data = new byte[length];
        int offset = 0;

        while (offset < length) {
            int bytesRead = input.read(data, offset, length - offset);

            if (bytesRead == -1) {
                if (offset == 0 && allowCleanEof) {
                    return null;
                }
                throw new EOFException("Unexpected end of PCAP file. Expected "
                        + length + " bytes but received " + offset + ".");
            }

            offset += bytesRead;
        }

        return data;
    }

    @Override
    public void close() throws IOException {
        input.close();
    }
}
