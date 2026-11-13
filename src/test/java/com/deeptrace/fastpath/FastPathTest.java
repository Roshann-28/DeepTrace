
package com.deeptrace.fastpath;

import com.deeptrace.classifier.AppType;
import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.parser.ParsedPacket;
import com.deeptrace.reader.PcapPacketHeader;
import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;
import com.deeptrace.rules.RuleDecision;
import com.deeptrace.rules.RuleEvaluator;
import com.deeptrace.rules.RuleManager;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class FastPathTest {

    // Helper method to create a YouTube HTTP packet
    private RawPacket createYouTubeHttpPacket() {

        byte[] payload = (
                "GET / HTTP/1.1\r\n" +
                        "Host: www.youtube.com\r\n" +
                        "Connection: close\r\n\r\n"
        ).getBytes(StandardCharsets.US_ASCII);

        int totalLength = 14 + 20 + 20 + payload.length;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength)
                .order(ByteOrder.BIG_ENDIAN);

        // Ethernet header
        buffer.put(new byte[]{
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x00, 0x11, 0x22, 0x33
        });
        buffer.putShort((short) 0x0800);

        // IPv4 header
        buffer.put((byte) 0x45);
        buffer.put((byte) 0);
        buffer.putShort((short) (20 + 20 + payload.length));
        buffer.putShort((short) 1);
        buffer.putShort((short) 0);
        buffer.put((byte) 64);
        buffer.put((byte) 6);
        buffer.putShort((short) 0);

        // Source IP: 10.0.0.1
        buffer.put(new byte[]{10, 0, 0, 1});

        // Destination IP: 142.250.1.1
        buffer.put(new byte[]{
                (byte) 142, (byte) 250, 1, 1
        });

        // TCP header
        buffer.putShort((short) 51515);
        buffer.putShort((short) 80);
        buffer.putInt(1);
        buffer.putInt(0);
        buffer.put((byte) 0x50);
        buffer.put((byte) 0x18);
        buffer.putShort((short) 8192);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);

        // HTTP payload
        buffer.put(payload);

        byte[] packetData = buffer.array();

        PcapPacketHeader header = new PcapPacketHeader(
                1, 0, packetData.length, packetData.length
        );

        return new RawPacket(header, packetData);
    }

    @Test
    void shouldProcessPacketsFromPcapFile() throws Exception {

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

        int processedPackets = 0;

        try (PcapReader reader =
                     new PcapReader(Path.of("test_dpi.pcap"))) {

            RawPacket rawPacket;

            while ((rawPacket = reader.nextPacket()) != null) {

                FastPath.FastPathResult result =
                        fastPath.process(rawPacket);

                assertNotNull(result);
                assertNotNull(result.packet());
                assertNotNull(result.detection());
                assertNotNull(result.decision());

                processedPackets++;
            }
        }

        assertTrue(processedPackets > 0);

        System.out.println(
                "FastPath processed packets: " + processedPackets
        );

        System.out.println(
                "Tracked connections: " + tracker.getConnectionCount()
        );
    }

    @Test
    void shouldBlockPacketWhenSourceIPIsBlocked() throws Exception {

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

        try (PcapReader reader =
                     new PcapReader(Path.of("test_dpi.pcap"))) {

            RawPacket rawPacket = reader.nextPacket();

            assertNotNull(rawPacket, "PCAP file contains no packets.");

            ParsedPacket parsedPacket = parser.parse(rawPacket);

            String sourceIP = parsedPacket.sourceIp();

            assertFalse(
                    sourceIP.isBlank(),
                    "First packet does not contain an IPv4 source address."
            );

            ruleManager.blockIP(sourceIP);

            FastPath.FastPathResult result =
                    fastPath.process(rawPacket);

            assertEquals(
                    RuleDecision.BLOCK,
                    result.decision()
            );
        }
    }

    @Test
    void shouldBlockYouTubeApplication() {

        RuleManager ruleManager = new RuleManager();

        ruleManager.blockApplication(AppType.YOUTUBE);

        FastPath fastPath = new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(ruleManager)
        );

        RawPacket rawPacket = createYouTubeHttpPacket();

        FastPath.FastPathResult result =
                fastPath.process(rawPacket);

        assertEquals(
                AppType.YOUTUBE,
                result.detection().applicationType()
        );

        assertEquals(
                RuleDecision.BLOCK,
                result.decision()
        );
    }

    @Test
    void shouldBlockYouTubeDomain() {

        RuleManager ruleManager = new RuleManager();

        ruleManager.blockDomain("youtube.com");

        FastPath fastPath = new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(ruleManager)
        );

        RawPacket rawPacket = createYouTubeHttpPacket();

        FastPath.FastPathResult result =
                fastPath.process(rawPacket);

        assertNotNull(result.detection().metadata());

        assertEquals(
                "www.youtube.com",
                result.detection().metadata().domain()
        );

        assertEquals(
                RuleDecision.BLOCK,
                result.decision()
        );
    }


    @Test
    void shouldAllowPacketWhenNoBlockingRulesMatch() {

        // Create an empty RuleManager
        RuleManager ruleManager = new RuleManager();

        FastPath fastPath = new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(ruleManager)
        );

        // Create a YouTube HTTP packet
        RawPacket rawPacket = createYouTubeHttpPacket();

        // Process the packet
        FastPath.FastPathResult result =
                fastPath.process(rawPacket);

        // Verify application detection
        assertEquals(
                AppType.YOUTUBE,
                result.detection().applicationType()
        );

        // Verify that the packet is allowed
        assertEquals(
                RuleDecision.ALLOW,
                result.decision()
        );

        assertTrue(result.isAllowed());
        assertFalse(result.isBlocked());
    }

}
