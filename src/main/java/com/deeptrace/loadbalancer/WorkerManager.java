
package com.deeptrace.loadbalancer;

import com.deeptrace.fastpath.FastPath;

import java.util.ArrayList;
import java.util.List;

public final class WorkerManager {

    private final LoadBalancer loadBalancer;
    private final List<PacketWorker> workers;

    private boolean started;

    public WorkerManager(
            LoadBalancer loadBalancer,
            FastPath fastPath
    ) {

        if (loadBalancer == null || fastPath == null) {
            throw new IllegalArgumentException(
                    "LoadBalancer and FastPath cannot be null."
            );
        }

        this.loadBalancer = loadBalancer;
        this.workers = new ArrayList<>();

        for (int i = 0; i < loadBalancer.getWorkerCount(); i++) {

            PacketWorker worker = new PacketWorker(
                    i,
                    loadBalancer,
                    fastPath
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
}
