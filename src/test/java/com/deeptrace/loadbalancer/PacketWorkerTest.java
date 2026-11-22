
package com.deeptrace.loadbalancer;

import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.fastpath.FastPath;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.reader.PcapPacketHeader;
import com.deeptrace.reader.RawPacket;
import com.deeptrace.rules.RuleEvaluator;
import com.deeptrace.rules.RuleManager;
import org.junit.jupiter.api.Test;
import com.deeptrace.pipeline.PacketProcessingResult;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class PacketWorkerTest {

    private FastPath createFastPath() {

        PacketParser parser = new PacketParser();

        ApplicationDetectionEngine detectionEngine =
                new ApplicationDetectionEngine();

        ConnectionTracker connectionTracker =
                new ConnectionTracker();

        RuleManager ruleManager = new RuleManager();

        RuleEvaluator ruleEvaluator =
                new RuleEvaluator(ruleManager);

        return new FastPath(
                parser,
                detectionEngine,
                connectionTracker,
                ruleEvaluator
        );
    }

    private RawPacket createRawPacket() {

        // Ethernet frame with an unsupported EtherType.
        // This is sufficient to test worker processing.
        byte[] data = new byte[]{
                0, 1, 2, 3, 4, 5,
                6, 7, 8, 9, 10, 11,
                0x08, 0x06
        };

        PcapPacketHeader header = new PcapPacketHeader(
                1000,
                0,
                data.length,
                data.length
        );

        return new RawPacket(header, data);
    }

    @Test
    void shouldRejectNullDependencies() {

        LoadBalancer loadBalancer = new LoadBalancer(2);
        FastPath fastPath = createFastPath();

        assertThrows(
                IllegalArgumentException.class,
                () -> new PacketWorker(0, null, fastPath)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new PacketWorker(0, loadBalancer, null)
        );
    }

    @Test
    void shouldRejectInvalidWorkerId() {

        LoadBalancer loadBalancer = new LoadBalancer(2);
        FastPath fastPath = createFastPath();

        assertThrows(
                IllegalArgumentException.class,
                () -> new PacketWorker(2, loadBalancer, fastPath)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new PacketWorker(-1, loadBalancer, fastPath)
        );
    }

    @Test
    void shouldStartAndStopWorker() throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        PacketWorker worker = new PacketWorker(
                0,
                loadBalancer,
                createFastPath()
        );

        worker.start();

        assertTrue(worker.isRunning());

        worker.stop();
        worker.awaitTermination();

        assertFalse(worker.isRunning());
    }

    @Test
    void shouldProcessPacketsFromItsQueue() throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        PacketWorker worker = new PacketWorker(
                0,
                loadBalancer,
                createFastPath()
        );

        worker.start();

        try {
            RawPacket packet = createRawPacket();

            loadBalancer.getQueueSize(0);

            // Put a packet directly into worker 0's queue.
            // Use a parsed packet to dispatch through the load balancer.
            var parsedPacket = new PacketParser().parse(packet);

            loadBalancer.dispatch(packet, parsedPacket);

            // Wait until the worker processes the packet.
            long deadline = System.currentTimeMillis() + 2000;

            while (worker.getProcessedPackets() < 1
                    && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }

            assertEquals(1, worker.getProcessedPackets());
            assertEquals(0, worker.getFailedPackets());

        } finally {
            worker.stop();
            worker.awaitTermination();
        }
    }

    @Test
    void shouldNotProcessPacketsAfterStopping()
            throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        PacketWorker worker = new PacketWorker(
                0,
                loadBalancer,
                createFastPath()
        );

        worker.start();

        worker.stop();
        worker.awaitTermination();

        assertFalse(worker.isRunning());
        assertEquals(0, worker.getProcessedPackets());
    }

    @Test
    void shouldRejectStartingWorkerTwice()
            throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        PacketWorker worker = new PacketWorker(
                0,
                loadBalancer,
                createFastPath()
        );

        worker.start();

        try {
            assertThrows(
                    IllegalStateException.class,
                    worker::start
            );
        } finally {
            worker.stop();
            worker.awaitTermination();
        }
    }


    @Test
    void shouldSendProcessingResultToOutputQueue() throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(1);

        BlockingQueue<PacketProcessingResult> outputQueue =
                new LinkedBlockingQueue<>();

        PacketWorker worker = new PacketWorker(
                0,
                loadBalancer,
                createFastPath(),
                outputQueue
        );

        worker.start();

        try {
            RawPacket packet = createRawPacket();

            var parsedPacket = new PacketParser().parse(packet);
            loadBalancer.dispatch(packet, parsedPacket);

            PacketProcessingResult result =
                    outputQueue.poll(2, TimeUnit.SECONDS);

            assertNotNull(result);
            assertEquals(1, worker.getProcessedPackets());
            assertEquals(0, worker.getFailedPackets());

        } finally {
            worker.stop();
            worker.awaitTermination();
        }
    }

    @Test
    void shouldPreserveOriginalPacketInProcessingResult()
            throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        BlockingQueue<PacketProcessingResult> outputQueue =
                new LinkedBlockingQueue<>();

        PacketWorker worker = new PacketWorker(
                0,
                loadBalancer,
                createFastPath(),
                outputQueue
        );

        worker.start();

        try {
            RawPacket originalPacket = createRawPacket();

            var parsedPacket = new PacketParser().parse(originalPacket);
            loadBalancer.dispatch(originalPacket, parsedPacket);

            PacketProcessingResult result =
                    outputQueue.poll(2, TimeUnit.SECONDS);

            assertNotNull(result);
            assertSame(originalPacket, result.rawPacket());
            assertNotNull(result.fastPathResult());
            assertTrue(result.isAllowed());
            assertFalse(result.isBlocked());

        } finally {
            worker.stop();
            worker.awaitTermination();
        }
    }

}
