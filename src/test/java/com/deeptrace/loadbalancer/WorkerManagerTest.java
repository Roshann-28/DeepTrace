
package com.deeptrace.loadbalancer;

import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.fastpath.FastPath;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.parser.ParsedPacket;
import com.deeptrace.reader.PcapPacketHeader;
import com.deeptrace.reader.RawPacket;
import com.deeptrace.rules.RuleEvaluator;
import com.deeptrace.rules.RuleManager;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WorkerManagerTest {

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

        PcapPacketHeader header = new PcapPacketHeader(
                1000, 0, data.length, data.length
        );

        return new RawPacket(header, data);
    }

    private ParsedPacket createParsedPacket() {

        return new ParsedPacket(
                "00:11:22:33:44:55",
                "AA:BB:CC:DD:EE:FF",
                0x0806,
                "",
                "",
                0,
                0,
                "OTHER",
                -1,
                -1,
                0,
                14,
                0,
                0,
                new byte[0]
        );
    }

    @Test
    void shouldRejectNullDependencies() {

        FastPath fastPath = createFastPath();
        LoadBalancer loadBalancer = new LoadBalancer(2);

        assertThrows(
                IllegalArgumentException.class,
                () -> new WorkerManager(null, fastPath)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new WorkerManager(loadBalancer, null)
        );
    }

    @Test
    void shouldCreateConfiguredNumberOfWorkers() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        WorkerManager manager = new WorkerManager(
                loadBalancer,
                createFastPath()
        );

        assertEquals(4, manager.getWorkerCount());

        for (int i = 0; i < 4; i++) {
            assertEquals(i, manager.getWorker(i).getWorkerId());
        }
    }

    @Test
    void shouldStartAndStopAllWorkers()
            throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        WorkerManager manager = new WorkerManager(
                loadBalancer,
                createFastPath()
        );

        manager.startAll();

        try {
            assertTrue(manager.areAllWorkersRunning());
        } finally {
            manager.stopAll();
            manager.awaitTermination();
        }

        assertFalse(manager.areAllWorkersRunning());
    }

    @Test
    void shouldRejectStartingWorkersTwice()
            throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        WorkerManager manager = new WorkerManager(
                loadBalancer,
                createFastPath()
        );

        manager.startAll();

        try {
            assertThrows(
                    IllegalStateException.class,
                    manager::startAll
            );
        } finally {
            manager.stopAll();
            manager.awaitTermination();
        }
    }

    @Test
    void shouldRejectInvalidWorkerId() {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        WorkerManager manager = new WorkerManager(
                loadBalancer,
                createFastPath()
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> manager.getWorker(-1)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> manager.getWorker(2)
        );
    }

    @Test
    void shouldProcessPacketsAcrossManagedWorkers()
            throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(2);

        WorkerManager manager = new WorkerManager(
                loadBalancer,
                createFastPath()
        );

        manager.startAll();

        try {
            for (int i = 0; i < 10; i++) {
                loadBalancer.dispatch(
                        createRawPacket(),
                        createParsedPacket()
                );
            }

            long deadline = System.currentTimeMillis() + 3000;

            while (manager.getTotalProcessedPackets() < 10
                    && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }

            assertEquals(10, manager.getTotalProcessedPackets());
            assertEquals(0, manager.getTotalFailedPackets());

        } finally {
            manager.stopAll();
            manager.awaitTermination();
        }
    }
}
