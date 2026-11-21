
package com.deeptrace.loadbalancer;

import com.deeptrace.fastpath.FastPath;
import com.deeptrace.reader.RawPacket;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import com.deeptrace.pipeline.PacketProcessingResult;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public final class PacketWorker implements Runnable {

    private final int workerId;
    private final LoadBalancer loadBalancer;
    private final FastPath fastPath;

    private final AtomicBoolean running = new AtomicBoolean(false);

    private final AtomicLong processedPackets = new AtomicLong(0);
    private final AtomicLong failedPackets = new AtomicLong(0);

    private volatile Thread workerThread;
    private volatile RuntimeException lastFailure;
    private final BlockingQueue<PacketProcessingResult> outputQueue;
    private volatile boolean gracefulShutdownRequested;

    public PacketWorker(
            int workerId,
            LoadBalancer loadBalancer,
            FastPath fastPath
    ) {
        this(workerId, loadBalancer, fastPath, null);
    }

    public PacketWorker(
            int workerId,
            LoadBalancer loadBalancer,
            FastPath fastPath,
            BlockingQueue<PacketProcessingResult> outputQueue
    ) {
        if (loadBalancer == null || fastPath == null) {
            throw new IllegalArgumentException(
                    "LoadBalancer and FastPath cannot be null."
            );
        }

        if (workerId < 0 || workerId >= loadBalancer.getWorkerCount()) {
            throw new IllegalArgumentException(
                    "Invalid worker ID: " + workerId
            );
        }

        this.workerId = workerId;
        this.loadBalancer = loadBalancer;
        this.fastPath = fastPath;
        this.outputQueue = outputQueue;
    }

    public synchronized void start() {

        if (workerThread != null) {
            throw new IllegalStateException(
                    "Worker has already been started."
            );
        }

        running.set(true);

        workerThread = new Thread(
                this,
                "DeepTrace-Worker-" + workerId
        );

        workerThread.start();
    }



    @Override
    public void run() {

        try {
            while (running.get()) {

                RawPacket packet = loadBalancer.pollPacket(
                        workerId,
                        100,
                        TimeUnit.MILLISECONDS
                );

                if (packet == null) {
                    if (gracefulShutdownRequested
                            && loadBalancer.getQueueSize(workerId) == 0) {
                        break;
                    }
                    continue;
                }

                try {
                    FastPath.FastPathResult result = fastPath.process(packet);

                    PacketProcessingResult processingResult =
                            new PacketProcessingResult(packet, result);

                    if (outputQueue != null) {
                        outputQueue.put(processingResult);
                    }

                    processedPackets.incrementAndGet();

                } catch (RuntimeException exception) {
                    lastFailure = exception;
                    failedPackets.incrementAndGet();
                }
            }

        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

        } finally {
            running.set(false);
        }
    }


    public void stop() {

        running.set(false);

        Thread thread = workerThread;

        if (thread != null) {
            thread.interrupt();
        }
    }

    public void awaitTermination() throws InterruptedException {

        Thread thread = workerThread;

        if (thread != null) {
            thread.join();
        }
    }

    public int getWorkerId() {
        return workerId;
    }

    public boolean isRunning() {
        return running.get();
    }

    public long getProcessedPackets() {
        return processedPackets.get();
    }

    public long getFailedPackets() {
        return failedPackets.get();
    }

    public RuntimeException getLastFailure() {
        return lastFailure;
    }

    public void gracefulStop() {
        gracefulShutdownRequested = true;
    }

}
