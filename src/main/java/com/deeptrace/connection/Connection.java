
package com.deeptrace.connection;

import com.deeptrace.classifier.AppType;
import com.deeptrace.parser.ParsedPacket;

public final class Connection {

    private final FiveTuple fiveTuple;
    private final long firstSeen;

    private long lastSeen;
    private long packetCount;
    private long totalBytes;
    private AppType applicationType;

    public Connection(FiveTuple fiveTuple, long timestamp) {
        if (fiveTuple == null) {
            throw new IllegalArgumentException("FiveTuple cannot be null.");
        }

        if (timestamp < 0) {
            throw new IllegalArgumentException("Timestamp cannot be negative.");
        }

        this.fiveTuple = fiveTuple;
        this.firstSeen = timestamp;
        this.lastSeen = timestamp;
        this.packetCount = 0;
        this.totalBytes = 0;
        this.applicationType = AppType.UNKNOWN;
    }

    public synchronized void update(ParsedPacket packet, long timestamp) {
        if (packet == null) {
            throw new IllegalArgumentException("Packet cannot be null.");
        }

        if (timestamp < lastSeen) {
            throw new IllegalArgumentException(
                    "Timestamp cannot be earlier than last seen time."
            );
        }

        lastSeen = timestamp;
        packetCount++;

        totalBytes += packet.payloadLength()
                + packet.ethernetHeaderLength()
                + packet.ipHeaderLength()
                + packet.transportHeaderLength();
    }

    public synchronized void setApplicationType(AppType applicationType) {
        if (applicationType == null) {
            throw new IllegalArgumentException(
                    "Application type cannot be null."
            );
        }

        this.applicationType = applicationType;
    }

    public FiveTuple getFiveTuple() {
        return fiveTuple;
    }

    public long getFirstSeen() {
        return firstSeen;
    }

    public synchronized long getLastSeen() {
        return lastSeen;
    }

    public synchronized long getPacketCount() {
        return packetCount;
    }

    public synchronized long getTotalBytes() {
        return totalBytes;
    }

    public synchronized AppType getApplicationType() {
        return applicationType;
    }

    public synchronized long getDuration() {
        return lastSeen - firstSeen;
    }
}
