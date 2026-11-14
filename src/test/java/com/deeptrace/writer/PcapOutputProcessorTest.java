
package com.deeptrace.writer;

import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;

import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.fastpath.FastPath;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.parser.ParsedPacket;
import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;
import com.deeptrace.rules.RuleEvaluator;
import com.deeptrace.rules.RuleManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PcapOutputProcessorTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldWriteOnlyAllowedPackets() throws IOException {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("filtered_output.pcap");

        PacketParser parser = new PacketParser();

        ApplicationDetectionEngine detectionEngine =
                new ApplicationDetectionEngine();

        ConnectionTracker tracker = new ConnectionTracker();
        RuleManager ruleManager = new RuleManager();

        RuleEvaluator evaluator = new RuleEvaluator(ruleManager);

        FastPath fastPath = new FastPath(
                parser,
                detectionEngine,
                tracker,
                evaluator
        );

        long allowedCount;
        long blockedCount;
        String blockedIP;

        // Read original packets and process them
        try (PcapReader reader = new PcapReader(inputFile)) {

            RawPacket firstPacket = reader.nextPacket();

            assertNotNull(firstPacket, "PCAP file contains no packets.");

            ParsedPacket parsedPacket = parser.parse(firstPacket);

            blockedIP = parsedPacket.sourceIp();

            assertFalse(
                    blockedIP.isBlank(),
                    "First packet must contain an IPv4 source address."
            );

            // Configure blocking rule
            ruleManager.blockIP(blockedIP);

            // Create output writer
            try (PcapWriter writer = new PcapWriter(
                    outputFile,
                    reader.getGlobalHeader()
            )) {

                PcapOutputProcessor processor =
                        new PcapOutputProcessor(fastPath, writer);

                // Process the first packet
                processor.processPacket(firstPacket);

                // Process remaining packets
                RawPacket packet;

                while ((packet = reader.nextPacket()) != null) {
                    processor.processPacket(packet);
                }

                allowedCount = processor.getAllowedPacketCount();
                blockedCount = processor.getBlockedPacketCount();

                assertEquals(
                        77,
                        processor.getProcessedPacketCount()
                );
            }
        }

        // Verify processing statistics
        assertTrue(blockedCount > 0);
        assertEquals(77, allowedCount + blockedCount);

        // Verify output contains only allowed packets
        int outputPacketCount = 0;

        try (PcapReader reader = new PcapReader(outputFile)) {

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {

                ParsedPacket parsed = parser.parse(packet);

                assertNotEquals(blockedIP, parsed.sourceIp());
                assertNotEquals(blockedIP, parsed.destinationIp());

                outputPacketCount++;
            }
        }

        assertEquals(allowedCount, outputPacketCount);

        System.out.println("Processed packets: 77");
        System.out.println("Allowed packets: " + allowedCount);
        System.out.println("Blocked packets: " + blockedCount);
        System.out.println("Output packets: " + outputPacketCount);
    }


    @Test
    void shouldWriteAllPacketsWhenNoRulesAreConfigured()
            throws IOException {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("all_allowed.pcap");

        RuleManager ruleManager = new RuleManager();

        FastPath fastPath = new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(ruleManager)
        );

        long allowed;
        long blocked;

        try (PcapReader reader = new PcapReader(inputFile);
             PcapWriter writer = new PcapWriter(
                     outputFile,
                     reader.getGlobalHeader()
             )) {

            PcapOutputProcessor processor =
                    new PcapOutputProcessor(fastPath, writer);

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {
                processor.processPacket(packet);
            }

            allowed = processor.getAllowedPacketCount();
            blocked = processor.getBlockedPacketCount();
        }

        assertEquals(77, allowed);
        assertEquals(0, blocked);

        // Verify output file contains all packets
        int outputCount = 0;

        try (PcapReader reader = new PcapReader(outputFile)) {

            while (reader.nextPacket() != null) {
                outputCount++;
            }
        }

        assertEquals(77, outputCount);
    }


    @Test
    void shouldCreateValidEmptyPcapWhenAllPacketsAreBlocked()
            throws IOException {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("all_blocked.pcap");

        PacketParser parser = new PacketParser();

        RuleManager ruleManager = new RuleManager();

        Set<String> ipAddresses = new HashSet<>();

        // First pass: Collect all IPv4 addresses
        try (PcapReader reader = new PcapReader(inputFile)) {

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {

                ParsedPacket parsed = parser.parse(packet);

                if (!parsed.sourceIp().isBlank()) {
                    ipAddresses.add(parsed.sourceIp());
                }

                if (!parsed.destinationIp().isBlank()) {
                    ipAddresses.add(parsed.destinationIp());
                }
            }
        }

        // Block every collected IP address
        for (String ip : ipAddresses) {
            ruleManager.blockIP(ip);
        }

        FastPath fastPath = new FastPath(
                parser,
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(ruleManager)
        );

        long allowed;
        long blocked;

        // Second pass: Process and filter packets
        try (PcapReader reader = new PcapReader(inputFile);
             PcapWriter writer = new PcapWriter(
                     outputFile,
                     reader.getGlobalHeader()
             )) {

            PcapOutputProcessor processor =
                    new PcapOutputProcessor(fastPath, writer);

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {
                processor.processPacket(packet);
            }

            allowed = processor.getAllowedPacketCount();
            blocked = processor.getBlockedPacketCount();
        }

        assertEquals(0, allowed);
        assertEquals(77, blocked);

        // Verify that the empty output is still a valid PCAP
        assertTrue(Files.exists(outputFile));

        try (PcapReader reader = new PcapReader(outputFile)) {

            assertNotNull(reader.getGlobalHeader());
            assertNull(reader.nextPacket());
            assertEquals(0, reader.getPacketCount());
        }
    }

}
