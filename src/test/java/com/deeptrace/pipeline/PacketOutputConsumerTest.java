
package com.deeptrace.pipeline;

import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.fastpath.FastPath;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;
import com.deeptrace.rules.RuleEvaluator;
import com.deeptrace.rules.RuleManager;
import com.deeptrace.writer.PcapWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.jupiter.api.Assertions.*;

class PacketOutputConsumerTest {

    @TempDir
    Path tempDir;

    private FastPath createFastPath() {
        return new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(new RuleManager())
        );
    }

    private RawPacket createRawPacket() {
        byte[] data = {
                0, 1, 2, 3, 4, 5,
                6, 7, 8, 9, 10, 11,
                0x08, 0x06
        };

        return new RawPacket(
                new com.deeptrace.reader.PcapPacketHeader(
                        1000, 0, data.length, data.length
                ),
                data
        );
    }

    private PacketProcessingResult createResult(
            RawPacket packet,
            boolean allowed
    ) {
        FastPath.FastPathResult result =
                createFastPath().process(packet);

        if (!allowed) {
            result = new FastPath.FastPathResult(
                    result.packet(),
                    result.detection(),
                    result.connection(),
                    com.deeptrace.rules.RuleDecision.BLOCK
            );
        }

        return new PacketProcessingResult(packet, result);
    }

    @Test
    void shouldWriteAllowedPackets() throws Exception {

        Path input = Path.of("test_dpi.pcap");
        Path output = tempDir.resolve("allowed.pcap");

        try (PcapReader reader = new PcapReader(input);
             PcapWriter writer = new PcapWriter(
                     output, reader.getGlobalHeader()
             )) {

            BlockingQueue<PacketProcessingResult> queue =
                    new LinkedBlockingQueue<>();

            PacketOutputConsumer consumer =
                    new PacketOutputConsumer(queue, writer);

            RawPacket packet = createRawPacket();

            consumer.start();
            queue.put(createResult(packet, true));
            consumer.finish();
            consumer.awaitTermination();

            assertEquals(1, consumer.getAllowedPackets());
            assertEquals(0, consumer.getBlockedPackets());
            assertEquals(0, consumer.getFailedPackets());
        }

        try (PcapReader outputReader = new PcapReader(output)) {
            assertNotNull(outputReader.nextPacket());
            assertNull(outputReader.nextPacket());
        }
    }

    @Test
    void shouldDiscardBlockedPackets() throws Exception {

        Path input = Path.of("test_dpi.pcap");
        Path output = tempDir.resolve("blocked.pcap");

        try (PcapReader reader = new PcapReader(input);
             PcapWriter writer = new PcapWriter(
                     output, reader.getGlobalHeader()
             )) {

            BlockingQueue<PacketProcessingResult> queue =
                    new LinkedBlockingQueue<>();

            PacketOutputConsumer consumer =
                    new PacketOutputConsumer(queue, writer);

            RawPacket packet = createRawPacket();

            consumer.start();
            queue.put(createResult(packet, false));
            consumer.finish();
            consumer.awaitTermination();

            assertEquals(0, consumer.getAllowedPackets());
            assertEquals(1, consumer.getBlockedPackets());
            assertEquals(0, consumer.getFailedPackets());
        }

        try (PcapReader outputReader = new PcapReader(output)) {
            assertNull(outputReader.nextPacket());
        }
    }

    @Test
    void shouldDrainQueueBeforeTerminating() throws Exception {

        Path input = Path.of("test_dpi.pcap");
        Path output = tempDir.resolve("drain.pcap");

        try (PcapReader reader = new PcapReader(input);
             PcapWriter writer = new PcapWriter(
                     output, reader.getGlobalHeader()
             )) {

            BlockingQueue<PacketProcessingResult> queue =
                    new LinkedBlockingQueue<>();

            PacketOutputConsumer consumer =
                    new PacketOutputConsumer(queue, writer);

            RawPacket packet = createRawPacket();

            consumer.start();

            queue.put(createResult(packet, true));
            queue.put(createResult(packet, true));
            queue.put(createResult(packet, false));

            consumer.finish();
            consumer.awaitTermination();

            assertEquals(2, consumer.getAllowedPackets());
            assertEquals(1, consumer.getBlockedPackets());
            assertEquals(0, consumer.getFailedPackets());
            assertEquals(0, queue.size());
        }

        try (PcapReader outputReader = new PcapReader(output)) {
            assertNotNull(outputReader.nextPacket());
            assertNotNull(outputReader.nextPacket());
            assertNull(outputReader.nextPacket());
        }
    }
}
