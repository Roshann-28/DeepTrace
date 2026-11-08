
package com.deeptrace;

import com.deeptrace.parser.PacketParser;
import com.deeptrace.parser.ParsedPacket;
import com.deeptrace.reader.PcapGlobalHeader;
import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;

import java.io.IOException;
import java.nio.file.Path;

public class Main {

    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("DeepTrace - Java Deep Packet Inspection System");
            System.out.println("Usage: java -jar deeptrace.jar <input.pcap>");
            return;
        }

        Path inputFile = Path.of(args[0]);

        PacketParser parser = new PacketParser();

        long parsedCount = 0;
        long failedCount = 0;

        try (PcapReader reader = new PcapReader(inputFile)) {

            PcapGlobalHeader header = reader.getGlobalHeader();

            // Our current parser supports Ethernet link-layer packets.
            if (header.getLinkType() != 1) {
                throw new IllegalArgumentException(
                        "Unsupported PCAP link type: " + header.getLinkType()
                                + ". Ethernet link type (1) is required."
                );
            }

            System.out.println("========================================");
            System.out.println("             DEEPTRACE");
            System.out.println("========================================");
            System.out.println("Input file : " + inputFile);
            System.out.println("PCAP       : " + header);
            System.out.println("----------------------------------------");

            RawPacket rawPacket;

            while ((rawPacket = reader.nextPacket()) != null) {

                try {

                    // Convert raw bytes into structured packet information.
                    ParsedPacket packet = parser.parse(rawPacket);

                    parsedCount++;

                    // Display the first 10 successfully parsed packets.
                    if (parsedCount <= 10) {

                        System.out.println(
                                "\nPacket #" + reader.getPacketCount()
                        );

                        System.out.println(
                                "Source MAC      : " + packet.sourceMac()
                        );

                        System.out.println(
                                "Destination MAC : " + packet.destinationMac()
                        );

                        System.out.println(
                                "EtherType       : 0x"
                                        + Integer.toHexString(packet.etherType())
                                        .toUpperCase()
                        );

                        System.out.println(
                                "Source IP       : " + packet.sourceIp()
                        );

                        System.out.println(
                                "Destination IP  : " + packet.destinationIp()
                        );

                        System.out.println(
                                "Transport       : " + packet.transportProtocol()
                        );

                        System.out.println(
                                "Source Port     : " + packet.sourcePort()
                        );

                        System.out.println(
                                "Destination Port: " + packet.destinationPort()
                        );

                        System.out.println(
                                "TTL             : " + packet.ttl()
                        );

                        System.out.println(
                                "Payload Length  : " + packet.payloadLength()
                        );

                        System.out.println("----------------------------------------");
                    }

                } catch (IllegalArgumentException exception) {

                    failedCount++;

                    if (failedCount <= 5) {
                        System.err.println(
                                "Failed to parse packet #"
                                        + reader.getPacketCount()
                                        + ": " + exception.getMessage()
                        );
                    }
                }
            }

            System.out.println("\n========================================");
            System.out.println("           DEEPTRACE SUMMARY");
            System.out.println("========================================");

            System.out.println(
                    "Total packets read   : " + reader.getPacketCount()
            );

            System.out.println(
                    "Successfully parsed  : " + parsedCount
            );

            System.out.println(
                    "Failed to parse      : " + failedCount
            );

            System.out.println("----------------------------------------");
            System.out.println("Phase 2 packet parsing completed.");

        } catch (IOException | IllegalArgumentException exception) {

            System.err.println(
                    "DeepTrace error: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
