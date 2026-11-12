
package com.deeptrace.connection;

import com.deeptrace.parser.ParsedPacket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConnectionTrackerTest {

    private final ConnectionTracker tracker = new ConnectionTracker();

    @Test
    void shouldCreateNewConnection() {
        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        Connection connection = tracker.processPacket(packet, 1000);

        assertNotNull(connection);
        assertEquals(1, tracker.getConnectionCount());
        assertEquals(1, connection.getPacketCount());
    }

    @Test
    void shouldReuseExistingConnection() {
        ParsedPacket outgoing = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        ParsedPacket incoming = createPacket(
                "142.250.183.14", 443,
                "192.168.1.5", 50001
        );

        Connection first = tracker.processPacket(outgoing, 1000);
        Connection second = tracker.processPacket(incoming, 1500);

        assertSame(first, second);
        assertEquals(1, tracker.getConnectionCount());
        assertEquals(2, second.getPacketCount());
    }

    @Test
    void shouldTrackDifferentConnectionsSeparately() {
        ParsedPacket firstPacket = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        ParsedPacket secondPacket = createPacket(
                "192.168.1.5", 50002,
                "142.250.183.14", 443
        );

        tracker.processPacket(firstPacket, 1000);
        tracker.processPacket(secondPacket, 1100);

        assertEquals(2, tracker.getConnectionCount());
    }

    @Test
    void shouldRetrieveConnection() {
        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        Connection created = tracker.processPacket(packet, 1000);

        Connection retrieved = tracker.getConnection(
                FiveTuple.from(packet)
        );

        assertSame(created, retrieved);
    }

    @Test
    void shouldRemoveConnection() {
        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        tracker.processPacket(packet, 1000);

        boolean removed = tracker.removeConnection(
                FiveTuple.from(packet)
        );

        assertTrue(removed);
        assertEquals(0, tracker.getConnectionCount());
    }

    @Test
    void shouldClearAllConnections() {
        tracker.processPacket(
                createPacket("192.168.1.5", 50001,
                        "142.250.183.14", 443),
                1000
        );

        tracker.processPacket(
                createPacket("192.168.1.5", 50002,
                        "142.250.183.14", 443),
                1100
        );

        tracker.clear();

        assertEquals(0, tracker.getConnectionCount());
    }

    @Test
    void shouldRejectNullPacket() {
        assertThrows(
                IllegalArgumentException.class,
                () -> tracker.processPacket(null, 1000)
        );
    }

    @Test
    void shouldExpireInactiveConnection() {
        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        tracker.processPacket(packet, 1000);

        int removed = tracker.expireInactiveConnections(1060, 60);

        assertEquals(1, removed);
        assertEquals(0, tracker.getConnectionCount());
    }

    @Test
    void shouldKeepActiveConnection() {
        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        tracker.processPacket(packet, 1000);

        int removed = tracker.expireInactiveConnections(1059, 60);

        assertEquals(0, removed);
        assertEquals(1, tracker.getConnectionCount());
    }

    @Test
    void shouldNotExpireConnectionUsingEarlierTimestamp() {
        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443
        );

        tracker.processPacket(packet, 1100);

        int removed = tracker.expireInactiveConnections(1050, 60);

        assertEquals(0, removed);
        assertEquals(1, tracker.getConnectionCount());
    }

    @Test
    void shouldRejectNegativeExpirationValues() {
        assertThrows(
                IllegalArgumentException.class,
                () -> tracker.expireInactiveConnections(-1, 60)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> tracker.expireInactiveConnections(1000, -1)
        );
    }

    private ParsedPacket createPacket(
            String sourceIp,
            int sourcePort,
            String destinationIp,
            int destinationPort
    ) {
        return new ParsedPacket(
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
                0x0800,
                sourceIp,
                destinationIp,
                64,
                6,
                "TCP",
                sourcePort,
                destinationPort,
                0,
                14,
                20,
                20,
                new byte[0]
        );
    }
}
