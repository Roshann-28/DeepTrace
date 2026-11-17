
package com.deeptrace.loadbalancer;

import com.deeptrace.connection.FiveTuple;
import com.deeptrace.parser.ParsedPacket;
import com.deeptrace.reader.RawPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public final class LoadBalancer {

    private static final int DEFAULT_QUEUE_CAPACITY = 1000;

    private final int workerCount;
    private final AtomicInteger roundRobinCounter;

    private final List<BlockingQueue<RawPacket>> workerQueues;

    public LoadBalancer(int workerCount) {
        this(workerCount, DEFAULT_QUEUE_CAPACITY);
    }

    public LoadBalancer(int workerCount, int queueCapacity) {

        if (workerCount <= 0) {
            throw new IllegalArgumentException(
                    "Worker count must be greater than zero."
            );
        }

        if (queueCapacity <= 0) {
            throw new IllegalArgumentException(
                    "Queue capacity must be greater than zero."
            );
        }

        this.workerCount = workerCount;
        this.roundRobinCounter = new AtomicInteger(0);

        this.workerQueues = new ArrayList<>();

        for (int i = 0; i < workerCount; i++) {
            workerQueues.add(
                    new ArrayBlockingQueue<>(queueCapacity)
            );
        }
    }

    public int selectWorker(ParsedPacket packet) {

        if (packet == null) {
            throw new IllegalArgumentException(
                    "Parsed packet cannot be null."
            );
        }

        String protocol = packet.transportProtocol();

        boolean isTrackable =
                ("TCP".equalsIgnoreCase(protocol)
                        || "UDP".equalsIgnoreCase(protocol))
                        && packet.sourceIp() != null
                        && !packet.sourceIp().isBlank()
                        && packet.destinationIp() != null
                        && !packet.destinationIp().isBlank()
                        && packet.sourcePort() >= 0
                        && packet.sourcePort() <= 65535
                        && packet.destinationPort() >= 0
                        && packet.destinationPort() <= 65535;

        if (isTrackable) {
            FiveTuple tuple = FiveTuple.from(packet);
            return selectWorker(tuple);
        }

        return Math.floorMod(
                roundRobinCounter.getAndIncrement(),
                workerCount
        );
    }

    private int selectWorker(FiveTuple tuple) {

        return Math.floorMod(
                tuple.hashCode(),
                workerCount
        );
    }

    public int dispatch(
            RawPacket rawPacket,
            ParsedPacket parsedPacket
    ) throws InterruptedException {

        if (rawPacket == null || parsedPacket == null) {
            throw new IllegalArgumentException(
                    "Raw packet and parsed packet cannot be null."
            );
        }

        int workerIndex = selectWorker(parsedPacket);

        // Waits if the selected worker's queue is full.
        workerQueues.get(workerIndex).put(rawPacket);

        return workerIndex;
    }

    public RawPacket takePacket(int workerIndex)
            throws InterruptedException {

        validateWorkerIndex(workerIndex);

        // Waits until a packet becomes available.
        return workerQueues.get(workerIndex).take();
    }

    public int getQueueSize(int workerIndex) {

        validateWorkerIndex(workerIndex);

        return workerQueues.get(workerIndex).size();
    }

    public int getQueueCapacity() {
        return workerQueues.get(0).size()
                + workerQueues.get(0).remainingCapacity();
    }

    public int getWorkerCount() {
        return workerCount;
    }

    private void validateWorkerIndex(int workerIndex) {

        if (workerIndex < 0 || workerIndex >= workerCount) {
            throw new IllegalArgumentException(
                    "Invalid worker index: " + workerIndex
            );
        }
    }
}
