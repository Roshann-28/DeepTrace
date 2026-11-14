
package com.deeptrace.writer;

import com.deeptrace.fastpath.FastPath;
import com.deeptrace.reader.RawPacket;

import java.io.IOException;

public final class PcapOutputProcessor {

    private final FastPath fastPath;
    private final PcapWriter pcapWriter;

    private long allowedPacketCount;
    private long blockedPacketCount;

    public PcapOutputProcessor(
            FastPath fastPath,
            PcapWriter pcapWriter
    ) {
        if (fastPath == null || pcapWriter == null) {
            throw new IllegalArgumentException(
                    "FastPath and PcapWriter cannot be null."
            );
        }

        this.fastPath = fastPath;
        this.pcapWriter = pcapWriter;
    }

    public FastPath.FastPathResult processPacket(
            RawPacket rawPacket
    ) throws IOException {

        if (rawPacket == null) {
            throw new IllegalArgumentException(
                    "Raw packet cannot be null."
            );
        }

        // Step 1: Process packet through FastPath
        FastPath.FastPathResult result =
                fastPath.process(rawPacket);

        // Step 2: Write only allowed packets
        if (result.isAllowed()) {

            pcapWriter.writePacket(rawPacket);
            allowedPacketCount++;

        } else {

            // Blocked packets are not written
            blockedPacketCount++;
        }

        return result;
    }

    public long getAllowedPacketCount() {
        return allowedPacketCount;
    }

    public long getBlockedPacketCount() {
        return blockedPacketCount;
    }

    public long getProcessedPacketCount() {
        return allowedPacketCount + blockedPacketCount;
    }
}
