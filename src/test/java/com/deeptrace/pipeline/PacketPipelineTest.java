package com.deeptrace.pipeline;

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
import com.deeptrace.parser.ParsedPacket;

import java.util.HashSet;
import java.util.Set;
import java.nio.file.Files;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PacketPipelineTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldProcessEntirePcapThroughPipeline() throws Exception {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("pipeline_output.pcap");

        // Create the FastPath dependencies
        PacketParser parser = new PacketParser();

        ApplicationDetectionEngine detectionEngine =
                new ApplicationDetectionEngine();

        ConnectionTracker connectionTracker =
                new ConnectionTracker();

        RuleManager ruleManager = new RuleManager();

        RuleEvaluator ruleEvaluator =
                new RuleEvaluator(ruleManager);

        FastPath fastPath = new FastPath(
                parser,
                detectionEngine,
                connectionTracker,
                ruleEvaluator
        );

        // Create and run the complete pipeline
        PacketPipeline pipeline = new PacketPipeline(
                inputFile,
                outputFile,
                4,
                fastPath
        );

        PacketPipeline.PipelineStats stats = pipeline.run();

        // Verify input packet count
        assertEquals(77, stats.packetsRead());

        // Verify processing
        assertEquals(77, stats.packetsProcessed());

        // Verify no failures
        assertEquals(0, stats.workerFailures());
        assertEquals(0, stats.routingFailures());
        assertEquals(0, stats.outputFailures());

        // With no blocking rules, every packet should be allowed
        assertEquals(77, stats.allowedPackets());
        assertEquals(0, stats.blockedPackets());

        // Verify output file exists
        assertTrue(
                java.nio.file.Files.exists(outputFile),
                "Output PCAP should exist."
        );

        // Verify output PCAP is valid and contains all allowed packets
        int outputPacketCount = 0;

        try (PcapReader reader = new PcapReader(outputFile)) {

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {
                outputPacketCount++;
            }
        }

        assertEquals(
                stats.allowedPackets(),
                outputPacketCount,
                "Output PCAP should contain only allowed packets."
        );

        assertEquals(77, outputPacketCount);

        System.out.println("===== PacketPipeline Integration Test =====");
        System.out.println("Packets read:       " + stats.packetsRead());
        System.out.println("Packets processed:   " + stats.packetsProcessed());
        System.out.println("Allowed packets:    " + stats.allowedPackets());
        System.out.println("Blocked packets:   " + stats.blockedPackets());
        System.out.println("Worker failures:    " + stats.workerFailures());
        System.out.println("Routing failures:   " + stats.routingFailures());
        System.out.println("Output failures:    " + stats.outputFailures());
        System.out.println("Output PCAP packets: " + outputPacketCount);
    }
    @Test
    void shouldFilterBlockedPacketsThroughPipeline() throws Exception {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("blocked_pipeline_output.pcap");

        PacketParser parser = new PacketParser();
        RuleManager ruleManager = new RuleManager();

        String blockedIP;

        // Step 1: Read the first packet and identify its source IP
        try (PcapReader reader = new PcapReader(inputFile)) {

            RawPacket firstPacket = reader.nextPacket();

            assertNotNull(firstPacket, "Input PCAP contains no packets.");

            blockedIP = parser.parse(firstPacket).sourceIp();

            assertFalse(
                    blockedIP.isBlank(),
                    "First packet must have a valid source IP."
            );
        }

        // Step 2: Configure a blocking rule
        ruleManager.blockIP(blockedIP);

        // Step 3: Create FastPath with the blocking rule
        FastPath fastPath = new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(ruleManager)
        );

        // Step 4: Run the pipeline
        PacketPipeline pipeline = new PacketPipeline(
                inputFile,
                outputFile,
                4,
                fastPath
        );

        PacketPipeline.PipelineStats stats = pipeline.run();

        // Step 5: Verify processing
        assertEquals(77, stats.packetsRead());
        assertEquals(77, stats.packetsProcessed());

        // Step 6: Verify filtering
        assertTrue(
                stats.blockedPackets() > 0,
                "At least one packet should be blocked."
        );

        assertEquals(
                77,
                stats.allowedPackets() + stats.blockedPackets(),
                "Every packet must be either allowed or blocked."
        );

        // Step 7: Verify there were no processing failures
        assertEquals(0, stats.workerFailures());
        assertEquals(0, stats.routingFailures());
        assertEquals(0, stats.outputFailures());

        // Step 8: Verify output PCAP contains only allowed packets
        int outputPacketCount = 0;

        try (PcapReader reader = new PcapReader(outputFile)) {

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {

                ParsedPacket parsed = parser.parse(packet);

                assertNotEquals(
                        blockedIP,
                        parsed.sourceIp(),
                        "Blocked IP must not appear as a packet source."
                );

                assertNotEquals(
                        blockedIP,
                        parsed.destinationIp(),
                        "Blocked IP must not appear as a packet destination."
                );

                outputPacketCount++;
            }
        }

        assertEquals(stats.allowedPackets(), outputPacketCount);

        System.out.println("===== Pipeline Filtering Test =====");
        System.out.println("Packets read:       " + stats.packetsRead());
        System.out.println("Packets processed:  " + stats.packetsProcessed());
        System.out.println("Allowed packets:    " + stats.allowedPackets());
        System.out.println("Blocked packets:    " + stats.blockedPackets());
        System.out.println("Output packets:     " + outputPacketCount);
    }

    @Test
    void shouldCreateValidEmptyPcapWhenAllPacketsAreBlocked() throws Exception {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("all_blocked_pipeline.pcap");

        PacketParser parser = new PacketParser();
        RuleManager ruleManager = new RuleManager();

        Set<String> ipAddresses = new HashSet<>();

        // Step 1: Collect all IP addresses from the input PCAP
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

        assertFalse(ipAddresses.isEmpty());

        // Step 2: Block every collected IP
        for (String ip : ipAddresses) {
            ruleManager.blockIP(ip);
        }

        // Step 3: Create FastPath with all blocking rules
        FastPath fastPath = new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(ruleManager)
        );

        // Step 4: Run the complete pipeline
        PacketPipeline pipeline = new PacketPipeline(
                inputFile,
                outputFile,
                4,
                fastPath
        );

        PacketPipeline.PipelineStats stats = pipeline.run();

        // Step 5: Verify processing
        assertEquals(77, stats.packetsRead());
        assertEquals(77, stats.packetsProcessed());

        // Step 6: Verify all packets are blocked
        assertEquals(0, stats.allowedPackets());
        assertEquals(77, stats.blockedPackets());

        // Step 7: Verify no processing failures
        assertEquals(0, stats.workerFailures());
        assertEquals(0, stats.routingFailures());
        assertEquals(0, stats.outputFailures());

        // Step 8: Verify output PCAP exists
        assertTrue(Files.exists(outputFile));

        // Step 9: Verify output PCAP is valid but empty
        try (PcapReader reader = new PcapReader(outputFile)) {

            assertNotNull(reader.getGlobalHeader());

            assertNull(
                    reader.nextPacket(),
                    "Output PCAP should contain no packets."
            );

            assertEquals(
                    0,
                    reader.getPacketCount(),
                    "Output PCAP packet count should be zero."
            );
        }

        System.out.println("===== All Blocked Pipeline Test =====");
        System.out.println("Packets read:       " + stats.packetsRead());
        System.out.println("Packets processed:  " + stats.packetsProcessed());
        System.out.println("Allowed packets:    " + stats.allowedPackets());
        System.out.println("Blocked packets:    " + stats.blockedPackets());
        System.out.println("Output packets:     0");
    }
}