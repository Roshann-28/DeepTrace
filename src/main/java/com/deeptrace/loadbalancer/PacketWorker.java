
package com.deeptrace.loadbalancer;

import com.deeptrace.fastpath.FastPath;
import com.deeptrace.reader.RawPacket;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class PacketWorker implements Runnable {

    private final int workerId;
    private final LoadBalancer loadBalancer;
    private final FastPath fastPath;

    private final AtomicBoolean running = new AtomicBoolean(false);

    private final AtomicLong processedPackets = new AtomicLong(0);
    private final AtomicLong failedPackets = new AtomicLong(0);

    private volatile Thread workerThread;
    private volatile RuntimeException lastFailure;

    public PacketWorker(
            int workerId,
            LoadBalancer loadBalancer,
            FastPath fastPath
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

        while (running.get()) {

            try {
                RawPacket packet =
                        loadBalancer.takePacket(workerId);

                fastPath.process(packet);

                processedPackets.incrementAndGet();

            } catch (InterruptedException exception) {

                Thread.currentThread().interrupt();
                break;

            } catch (RuntimeException exception) {

                lastFailure = exception;
                failedPackets.incrementAndGet();
            }
        }

        running.set(false);
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
}
