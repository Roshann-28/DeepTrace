
package com.deeptrace.connection;

import com.deeptrace.classifier.AppType;
import com.deeptrace.parser.ParsedPacket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConnectionTest {

    @Test
    void shouldInitializeConnection() {
        FiveTuple tuple = createTuple();

        Connection connection = new Connection(tuple, 1000);

        assertEquals(tuple, connection.getFiveTuple());
        assertEquals(1000, connection.getFirstSeen());
        assertEquals(1000, connection.getLastSeen());
        assertEquals(0, connection.getPacketCount());
        assertEquals(0, connection.getTotalBytes());
        assertEquals(AppType.UNKNOWN, connection.getApplicationType());
    }

    @Test
    void shouldUpdatePacketStatistics() {
        Connection connection = new Connection(createTuple(), 1000);

        ParsedPacket packet = createPacket();

        connection.update(packet, 1500);

        assertEquals(1, connection.getPacketCount());
        assertEquals(54, connection.getTotalBytes());
        assertEquals(1500, connection.getLastSeen());
        assertEquals(500, connection.getDuration());
    }

    @Test
    void shouldUpdateMultiplePackets() {
        Connection connection = new Connection(createTuple(), 1000);

        ParsedPacket packet = createPacket();

        connection.update(packet, 1500);
        connection.update(packet, 2000);

        assertEquals(2, connection.getPacketCount());
        assertEquals(108, connection.getTotalBytes());
        assertEquals(2000, connection.getLastSeen());
        assertEquals(1000, connection.getDuration());
    }

    @Test
    void shouldSetApplicationType() {
        Connection connection = new Connection(createTuple(), 1000);

        connection.setApplicationType(AppType.YOUTUBE);

        assertEquals(AppType.YOUTUBE, connection.getApplicationType());
    }

    @Test
    void shouldRejectNullTuple() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Connection(null, 1000)
        );
    }

    @Test
    void shouldRejectNullPacket() {
        Connection connection = new Connection(createTuple(), 1000);

        assertThrows(
                IllegalArgumentException.class,
                () -> connection.update(null, 1500)
        );
    }

    private FiveTuple createTuple() {
        return new FiveTuple(
                "192.168.1.5", 50001,
                "142.250.183.14", 443,
                "TCP"
        );
    }

    private ParsedPacket createPacket() {
        return new ParsedPacket(
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
                0x0800,
                "192.168.1.5",
                "142.250.183.14",
                64,
                6,
                "TCP",
                50001,
                443,
                0,
                14,
                20,
                20,
                new byte[0]
        );
    }
}
