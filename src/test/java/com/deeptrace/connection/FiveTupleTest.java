
package com.deeptrace.connection;

import com.deeptrace.parser.ParsedPacket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FiveTupleTest {

    @Test
    void shouldCreateFiveTupleFromTcpPacket() {

        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443,
                "TCP"
        );

        FiveTuple tuple = FiveTuple.from(packet);

        assertEquals("142.250.183.14", tuple.sourceIp());
        assertEquals(443, tuple.sourcePort());
        assertEquals("192.168.1.5", tuple.destinationIp());
        assertEquals(50001, tuple.destinationPort());
        assertEquals("TCP", tuple.protocol());
    }

    @Test
    void shouldTreatReversePacketsAsSameConnection() {

        ParsedPacket outgoing = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443,
                "TCP"
        );

        ParsedPacket incoming = createPacket(
                "142.250.183.14", 443,
                "192.168.1.5", 50001,
                "TCP"
        );

        assertEquals(
                FiveTuple.from(outgoing),
                FiveTuple.from(incoming)
        );
    }

    @Test
    void shouldTreatUdpAsDifferentProtocol() {

        ParsedPacket tcpPacket = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443,
                "TCP"
        );

        ParsedPacket udpPacket = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443,
                "UDP"
        );

        assertNotEquals(
                FiveTuple.from(tcpPacket),
                FiveTuple.from(udpPacket)
        );
    }

    @Test
    void shouldRejectNullPacket() {

        assertThrows(
                IllegalArgumentException.class,
                () -> FiveTuple.from(null)
        );
    }

    @Test
    void shouldRejectUnsupportedProtocol() {

        ParsedPacket packet = createPacket(
                "192.168.1.5", 50001,
                "142.250.183.14", 443,
                "OTHER"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> FiveTuple.from(packet)
        );
    }

    private ParsedPacket createPacket(
            String sourceIp,
            int sourcePort,
            String destinationIp,
            int destinationPort,
            String protocol
    ) {
        return new ParsedPacket(
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
                0x0800,
                sourceIp,
                destinationIp,
                64,
                protocol.equals("TCP") ? 6 : 17,
                protocol,
                sourcePort,
                destinationPort,
                0,
                14,
                20,
                protocol.equals("TCP") ? 20 : 8,
                new byte[0]
        );
    }
}
