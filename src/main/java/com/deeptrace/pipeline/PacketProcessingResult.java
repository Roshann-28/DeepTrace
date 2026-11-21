
package com.deeptrace.pipeline;

import com.deeptrace.fastpath.FastPath;
import com.deeptrace.reader.RawPacket;

public record PacketProcessingResult(
        RawPacket rawPacket,
        FastPath.FastPathResult fastPathResult
) {
    public PacketProcessingResult {
        if (rawPacket == null) {
            throw new IllegalArgumentException("RawPacket cannot be null.");
        }

        if (fastPathResult == null) {
            throw new IllegalArgumentException("FastPathResult cannot be null.");
        }
    }

    public boolean isAllowed() {
        return fastPathResult.isAllowed();
    }

    public boolean isBlocked() {
        return fastPathResult.isBlocked();
    }
}
