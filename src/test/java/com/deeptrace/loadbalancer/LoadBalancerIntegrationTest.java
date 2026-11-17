
package com.deeptrace.loadbalancer;

import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.fastpath.FastPath;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;
import com.deeptrace.rules.RuleEvaluator;
import com.deeptrace.rules.RuleManager;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class LoadBalancerIntegrationTest {

    private FastPath createFastPath() {

        return new FastPath(
                new PacketParser(),
                new ApplicationDetectionEngine(),
                new ConnectionTracker(),
                new RuleEvaluator(new RuleManager())
        );
    }

    @Test
    void shouldProcessAllPcapPacketsAcrossMultipleWorkers()
            throws Exception {

        Path inputPath = Path.of("test_dpi.pcap");

        int workerCount = 4;
        int packetsRead = 0;

        LoadBalancer loadBalancer = new LoadBalancer(workerCount);

        WorkerManager manager = new WorkerManager(
                loadBalancer,
                createFastPath()
        );

        manager.startAll();

        try {

            try (PcapReader reader = new PcapReader(inputPath)) {

                RawPacket rawPacket;

                PacketParser packetParser = new PacketParser();

                while ((rawPacket = reader.nextPacket()) != null) {

                    var parsedPacket = packetParser.parse(rawPacket);

                    loadBalancer.dispatch(
                            rawPacket,
                            parsedPacket
                    );

                    packetsRead++;
                }
            }

            // Wait until all dispatched packets are processed.
            long deadline = System.currentTimeMillis() + 5000;

            while (manager.getTotalProcessedPackets() < packetsRead
                    && System.currentTimeMillis() < deadline) {

                Thread.sleep(10);
            }

            assertEquals(
                    77,
                    packetsRead,
                    "The input PCAP should contain 77 packets."
            );

            assertEquals(
                    packetsRead,
                    manager.getTotalProcessedPackets(),
                    "Every input packet should be processed."
            );

            assertEquals(
                    0,
                    manager.getTotalFailedPackets(),
                    "No worker should fail while processing packets."
            );

            for (int i = 0; i < workerCount; i++) {
                assertEquals(
                        0,
                        loadBalancer.getQueueSize(i),
                        "Worker queue should be empty after processing."
                );
            }

        } finally {

            manager.stopAll();
            manager.awaitTermination();
        }
    }
}
