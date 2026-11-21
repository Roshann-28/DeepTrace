
package com.deeptrace.pipeline;

import com.deeptrace.writer.PcapWriter;

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public final class PacketOutputConsumer implements Runnable {

    private final BlockingQueue<PacketProcessingResult> outputQueue;
    private final PcapWriter pcapWriter;

    private final AtomicLong allowedPackets = new AtomicLong(0);
    private final AtomicLong blockedPackets = new AtomicLong(0);
    private final AtomicLong failedPackets = new AtomicLong(0);

    private volatile boolean running;
    private volatile boolean producerFinished;
    private volatile Thread consumerThread;
    private volatile IOException lastFailure;

    public PacketOutputConsumer(
            BlockingQueue<PacketProcessingResult> outputQueue,
            PcapWriter pcapWriter
    ) {
        if (outputQueue == null || pcapWriter == null) {
            throw new IllegalArgumentException(
                    "Output queue and PcapWriter cannot be null."
            );
        }

        this.outputQueue = outputQueue;
        this.pcapWriter = pcapWriter;
    }

    public synchronized void start() {
        if (consumerThread != null) {
            throw new IllegalStateException(
                    "Output consumer has already been started."
            );
        }

        running = true;

        consumerThread = new Thread(
                this,
                "DeepTrace-Output-Consumer"
        );

        consumerThread.start();
    }

    @Override
    public void run() {
        try {
            while (running || !outputQueue.isEmpty()) {

                PacketProcessingResult result =
                        outputQueue.poll(100, TimeUnit.MILLISECONDS);

                if (result == null) {
                    continue;
                }

                try {
                    if (result.isAllowed()) {
                        pcapWriter.writePacket(result.rawPacket());
                        allowedPackets.incrementAndGet();
                    } else {
                        blockedPackets.incrementAndGet();
                    }
                } catch (IOException exception) {
                    lastFailure = exception;
                    failedPackets.incrementAndGet();
                }
            }

        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

        } finally {
            running = false;
        }
    }

    public void finish() {
        producerFinished = true;
        running = false;
    }

    public void awaitTermination() throws InterruptedException {
        Thread thread = consumerThread;

        if (thread != null) {
            thread.join();
        }
    }

    public boolean isRunning() {
        return running;
    }

    public boolean isProducerFinished() {
        return producerFinished;
    }

    public long getAllowedPackets() {
        return allowedPackets.get();
    }

    public long getBlockedPackets() {
        return blockedPackets.get();
    }

    public long getFailedPackets() {
        return failedPackets.get();
    }

    public long getProcessedPackets() {
        return allowedPackets.get() + blockedPackets.get() + failedPackets.get();
    }

    public IOException getLastFailure() {
        return lastFailure;
    }
}
