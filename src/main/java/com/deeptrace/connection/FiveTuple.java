
package com.deeptrace.connection;

import com.deeptrace.parser.ParsedPacket;

import java.util.Locale;
import java.util.Objects;

public record FiveTuple(
        String sourceIp,
        int sourcePort,
        String destinationIp,
        int destinationPort,
        String protocol
) {

    public FiveTuple {
        if (sourceIp == null || sourceIp.isBlank()
                || destinationIp == null || destinationIp.isBlank()) {
            throw new IllegalArgumentException("IP addresses cannot be empty.");
        }

        if (sourcePort < 0 || sourcePort > 65535
                || destinationPort < 0 || destinationPort > 65535) {
            throw new IllegalArgumentException("Invalid port number.");
        }

        if (protocol == null || protocol.isBlank()) {
            throw new IllegalArgumentException("Protocol cannot be empty.");
        }

        protocol = protocol.trim().toUpperCase(Locale.ROOT);
    }

    public static FiveTuple from(ParsedPacket packet) {

        if (packet == null) {
            throw new IllegalArgumentException("Parsed packet cannot be null.");
        }

        String sourceIp = packet.sourceIp();
        String destinationIp = packet.destinationIp();

        int sourcePort = packet.sourcePort();
        int destinationPort = packet.destinationPort();

        String protocol = packet.transportProtocol();

        if (!protocol.equalsIgnoreCase("TCP")
                && !protocol.equalsIgnoreCase("UDP")) {
            throw new IllegalArgumentException(
                    "Only TCP and UDP packets can be tracked."
            );
        }

        // Normalize both directions into the same connection key.
        boolean reverseOrder =
                sourceIp.compareTo(destinationIp) > 0
                        || (sourceIp.equals(destinationIp)
                        && sourcePort > destinationPort);

        if (reverseOrder) {
            return new FiveTuple(
                    destinationIp,
                    destinationPort,
                    sourceIp,
                    sourcePort,
                    protocol
            );
        }

        return new FiveTuple(
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort,
                protocol
        );
    }

    public boolean matches(ParsedPacket packet) {
        return equals(FiveTuple.from(packet));
    }
}
