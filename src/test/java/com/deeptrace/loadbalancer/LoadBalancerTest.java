
package com.deeptrace.loadbalancer;


import com.deeptrace.reader.RawPacket;
import com.deeptrace.reader.PcapPacketHeader;


import com.deeptrace.parser.ParsedPacket;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class LoadBalancerTest {

    private ParsedPacket createPacket(
            String sourceIp,
            int sourcePort,
            String destinationIp,
            int destinationPort,
            String protocol
    ) {
        return new ParsedPacket(
                "00:11:22:33:44:55",
                "AA:BB:CC:DD:EE:FF",
                0x0800,
                sourceIp,
                destinationIp,
                64,
                protocol.equals("TCP") ? 6 : 17,
                protocol,
                sourcePort,
                destinationPort,
                0,
                14,
                20,
                protocol.equals("TCP") ? 20 : 8,
                new byte[]{1, 2, 3}
        );
    }

    @Test
    void shouldRejectZeroWorkers() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new LoadBalancer(0)
        );
    }

    @Test
    void shouldRejectNegativeWorkerCount() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new LoadBalancer(-2)
        );
    }

    @Test
    void shouldAssignSameFlowToSameWorker() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        ParsedPacket packet1 = createPacket(
                "192.168.1.10", 5000,
                "142.250.190.14", 443,
                "TCP"
        );

        ParsedPacket packet2 = createPacket(
                "192.168.1.10", 5000,
                "142.250.190.14", 443,
                "TCP"
        );

        int worker1 = loadBalancer.selectWorker(packet1);
        int worker2 = loadBalancer.selectWorker(packet2);

        assertEquals(worker1, worker2);
    }

    @Test
    void shouldAssignBothDirectionsOfSameFlowToSameWorker() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        ParsedPacket outgoingPacket = createPacket(
                "192.168.1.10", 5000,
                "142.250.190.14", 443,
                "TCP"
        );

        ParsedPacket incomingPacket = createPacket(
                "142.250.190.14", 443,
                "192.168.1.10", 5000,
                "TCP"
        );

        int outgoingWorker =
                loadBalancer.selectWorker(outgoingPacket);

        int incomingWorker =
                loadBalancer.selectWorker(incomingPacket);

        assertEquals(outgoingWorker, incomingWorker);
    }

    @Test
    void shouldDistributeDifferentFlowsAcrossWorkers() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        Set<Integer> selectedWorkers = new HashSet<>();

        for (int i = 1; i <= 100; i++) {

            ParsedPacket packet = createPacket(
                    "192.168.1." + i,
                    5000 + i,
                    "142.250.190.14",
                    443,
                    "TCP"
            );

            selectedWorkers.add(
                    loadBalancer.selectWorker(packet)
            );
        }

        assertTrue(
                selectedWorkers.size() > 1,
                "Different flows should be distributed across workers."
        );
    }

    @Test
    void shouldUseRoundRobinForNonTcpUdpPackets() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        ParsedPacket packet = createPacket(
                "",
                -1,
                "",
                -1,
                "OTHER"
        );

        assertEquals(0, loadBalancer.selectWorker(packet));
        assertEquals(1, loadBalancer.selectWorker(packet));
        assertEquals(2, loadBalancer.selectWorker(packet));
        assertEquals(3, loadBalancer.selectWorker(packet));
        assertEquals(0, loadBalancer.selectWorker(packet));
    }

    @Test
    void shouldRejectNullPacket() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        assertThrows(
                IllegalArgumentException.class,
                () -> loadBalancer.selectWorker(null)
        );
    }

    @Test
    void shouldReturnConfiguredWorkerCount() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        assertEquals(4, loadBalancer.getWorkerCount());
    }


    private RawPacket createRawPacket() {

        byte[] data = new byte[]{1, 2, 3};

        PcapPacketHeader header = new PcapPacketHeader(
                1000,
                0,
                data.length,
                data.length
        );

        return new RawPacket(header, data);
    }


    @Test
    void shouldDispatchPacketToSelectedWorker() throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        ParsedPacket parsedPacket = createPacket(
                "192.168.1.10", 5000,
                "142.250.190.14", 443,
                "TCP"
        );

        RawPacket rawPacket = createRawPacket();

        int workerIndex = loadBalancer.dispatch(
                rawPacket,
                parsedPacket
        );

        assertEquals(1, loadBalancer.getQueueSize(workerIndex));
    }


    @Test
    void shouldRetrievePacketFromWorkerQueue() throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        ParsedPacket parsedPacket = createPacket(
                "192.168.1.10", 5000,
                "142.250.190.14", 443,
                "TCP"
        );

        RawPacket rawPacket = createRawPacket();

        int workerIndex = loadBalancer.dispatch(
                rawPacket,
                parsedPacket
        );

        RawPacket retrievedPacket =
                loadBalancer.takePacket(workerIndex);

        assertSame(rawPacket, retrievedPacket);

        assertEquals(0, loadBalancer.getQueueSize(workerIndex));
    }


    @Test
    void shouldDispatchSameFlowToSameQueue() throws InterruptedException {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        ParsedPacket outgoingPacket = createPacket(
                "192.168.1.10", 5000,
                "142.250.190.14", 443,
                "TCP"
        );

        ParsedPacket incomingPacket = createPacket(
                "142.250.190.14", 443,
                "192.168.1.10", 5000,
                "TCP"
        );

        int firstWorker = loadBalancer.dispatch(
                createRawPacket(),
                outgoingPacket
        );

        int secondWorker = loadBalancer.dispatch(
                createRawPacket(),
                incomingPacket
        );

        assertEquals(firstWorker, secondWorker);
        assertEquals(2, loadBalancer.getQueueSize(firstWorker));
    }


    @Test
    void shouldRejectInvalidWorkerIndex() {

        LoadBalancer loadBalancer = new LoadBalancer(4);

        assertThrows(
                IllegalArgumentException.class,
                () -> loadBalancer.getQueueSize(4)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> loadBalancer.getQueueSize(-1)
        );
    }


    @Test
    void shouldRejectInvalidQueueCapacity() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new LoadBalancer(4, 0)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new LoadBalancer(4, -1)
        );
    }

}
