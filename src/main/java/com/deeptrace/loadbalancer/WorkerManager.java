
package com.deeptrace.loadbalancer;

import com.deeptrace.fastpath.FastPath;
import com.deeptrace.pipeline.PacketProcessingResult;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;

public final class WorkerManager {

    private final LoadBalancer loadBalancer;
    private final List<PacketWorker> workers;

    private boolean started;

    // Phase 10: Shared output queue
    private final BlockingQueue<PacketProcessingResult> outputQueue;

    // Existing Phase 9 constructor (backward compatibility)
    public WorkerManager(
            LoadBalancer loadBalancer,
            FastPath fastPath
    ) {
        this(loadBalancer, fastPath, null);
    }

    // Phase 10 constructor
    public WorkerManager(
            LoadBalancer loadBalancer,
            FastPath fastPath,
            BlockingQueue<PacketProcessingResult> outputQueue
    ) {

        if (loadBalancer == null || fastPath == null) {
            throw new IllegalArgumentException(
                    "LoadBalancer and FastPath cannot be null."
            );
        }

        this.loadBalancer = loadBalancer;
        this.outputQueue = outputQueue;
        this.workers = new ArrayList<>();

        for (int i = 0; i < loadBalancer.getWorkerCount(); i++) {

            PacketWorker worker = new PacketWorker(
                    i,
                    loadBalancer,
                    fastPath,
                    outputQueue
            );

            workers.add(worker);
        }
    }

    public synchronized void startAll() {

        if (started) {
            throw new IllegalStateException(
                    "Workers have already been started."
            );
        }

        started = true;

        try {
            for (PacketWorker worker : workers) {
                worker.start();
            }
        } catch (RuntimeException exception) {
            stopAll();
            throw exception;
        }
    }

    public void stopAll() {

        for (PacketWorker worker : workers) {
            worker.stop();
        }
    }

    public void gracefulStopAll() {

        for (PacketWorker worker : workers) {
            worker.gracefulStop();
        }
    }


    public void awaitTermination() throws InterruptedException {

        for (PacketWorker worker : workers) {
            worker.awaitTermination();
        }
    }

    public int getWorkerCount() {
        return workers.size();
    }

    public PacketWorker getWorker(int workerId) {

        if (workerId < 0 || workerId >= workers.size()) {
            throw new IllegalArgumentException(
                    "Invalid worker ID: " + workerId
            );
        }

        return workers.get(workerId);
    }

    public long getTotalProcessedPackets() {

        long total = 0;

        for (PacketWorker worker : workers) {
            total += worker.getProcessedPackets();
        }

        return total;
    }

    public long getTotalFailedPackets() {

        long total = 0;

        for (PacketWorker worker : workers) {
            total += worker.getFailedPackets();
        }

        return total;
    }

    public boolean areAllWorkersRunning() {

        for (PacketWorker worker : workers) {
            if (!worker.isRunning()) {
                return false;
            }
        }

        return true;
    }

    // Phase 10: Access to shared output queue
    public BlockingQueue<PacketProcessingResult> getOutputQueue() {
        return outputQueue;
    }
}
