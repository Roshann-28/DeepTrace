
package com.deeptrace.connection;
import java.util.concurrent.atomic.AtomicInteger;

import com.deeptrace.parser.ParsedPacket;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class ConnectionTracker {

    private final ConcurrentMap<FiveTuple, Connection> connections =
            new ConcurrentHashMap<>();

    public Connection processPacket(ParsedPacket packet, long timestamp) {

        if (packet == null) {
            throw new IllegalArgumentException("Packet cannot be null.");
        }

        FiveTuple tuple = FiveTuple.from(packet);

        return connections.compute(tuple, (key, existing) -> {

            if (existing == null) {
                existing = new Connection(key, timestamp);
            }

            existing.update(packet, timestamp);

            return existing;
        });
    }

    public Connection getConnection(FiveTuple tuple) {
        if (tuple == null) {
            return null;
        }

        return connections.get(tuple);
    }

    public int getConnectionCount() {
        return connections.size();
    }

    public boolean removeConnection(FiveTuple tuple) {
        if (tuple == null) {
            return false;
        }

        return connections.remove(tuple) != null;
    }

    public void clear() {
        connections.clear();
    }

    public int expireInactiveConnections(
            long currentTimestamp,
            long idleTimeout
    ) {
        if (currentTimestamp < 0 || idleTimeout < 0) {
            throw new IllegalArgumentException(
                    "Timestamp and idle timeout cannot be negative."
            );
        }

        AtomicInteger removedCount = new AtomicInteger(0);

        connections.forEach((tuple, connection) -> {

            connections.computeIfPresent(tuple, (key, current) -> {

                long lastSeen = current.getLastSeen();

                if (currentTimestamp >= lastSeen
                        && currentTimestamp - lastSeen >= idleTimeout) {

                    removedCount.incrementAndGet();
                    return null;
                }

                return current;
            });
        });

        return removedCount.get();
    }
}
