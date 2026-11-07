package com.deeptrace;

import com.deeptrace.reader.PcapGlobalHeader;
import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Entry point for the DeepTrace application.
 */
public class Main {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("DeepTrace - Java Deep Packet Inspection System");
            System.out.println("Usage: java -jar deeptrace.jar <input.pcap>");
            return;
        }

        Path inputFile = Path.of(args[0]);

        try (PcapReader reader = new PcapReader(inputFile)) {
            PcapGlobalHeader header = reader.getGlobalHeader();

            System.out.println("========================================");
            System.out.println("             DEEPTRACE");
            System.out.println("========================================");
            System.out.println("Input file : " + inputFile);
            System.out.println("PCAP       : " + header);
            System.out.println("----------------------------------------");

            RawPacket packet;
            while ((packet = reader.nextPacket()) != null) {
                if (reader.getPacketCount() <= 5) {
                    System.out.printf(
                            "Packet %-4d | captured=%-6d | original=%-6d | timestamp=%d.%d%n",
                            reader.getPacketCount(),
                            packet.header().capturedLength(),
                            packet.header().originalLength(),
                            packet.header().timestampSeconds(),
                            packet.header().timestampFraction());
                }
            }

            System.out.println("----------------------------------------");
            System.out.println("Total packets read: " + reader.getPacketCount());
            System.out.println("Phase 1 PCAP reading completed.");
        } catch (IOException | IllegalArgumentException exception) {
            System.err.println("Failed to read PCAP file: " + exception.getMessage());
            System.exit(1);
        }
    }
}
