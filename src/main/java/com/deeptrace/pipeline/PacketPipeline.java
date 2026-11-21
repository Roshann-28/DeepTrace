
package com.deeptrace.pipeline;

import com.deeptrace.fastpath.FastPath;
import com.deeptrace.loadbalancer.LoadBalancer;
import com.deeptrace.loadbalancer.WorkerManager;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.parser.ParsedPacket;
import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;
import com.deeptrace.writer.PcapWriter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public final class PacketPipeline {

    private static final int DEFAULT_QUEUE_CAPACITY = 1000;

    private final Path inputPath;
    private final Path outputPath;
    private final int workerCount;
    private final int queueCapacity;
    private final FastPath fastPath;

    public PacketPipeline(
            Path inputPath,
            Path outputPath,
            int workerCount,
            FastPath fastPath) {

        this(inputPath, outputPath, workerCount,
                DEFAULT_QUEUE_CAPACITY, fastPath);
    }

    public PacketPipeline(
            Path inputPath,
            Path outputPath,
            int workerCount,
            int queueCapacity,
            FastPath fastPath) {

        if (inputPath == null || outputPath == null || fastPath == null) {
            throw new IllegalArgumentException(
                    "Paths and FastPath cannot be null.");
        }

        if (workerCount <= 0 || queueCapacity <= 0) {
            throw new IllegalArgumentException(
                    "Worker count and queue capacity must be positive.");
        }

        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.workerCount = workerCount;
        this.queueCapacity = queueCapacity;
        this.fastPath = fastPath;
    }

    public PipelineStats run() throws IOException, InterruptedException {

        PacketParser packetParser = new PacketParser();

        LoadBalancer loadBalancer =
                new LoadBalancer(workerCount, queueCapacity);

        BlockingQueue<PacketProcessingResult> outputQueue =
                new LinkedBlockingQueue<>(queueCapacity);

        WorkerManager workerManager = null;
        PacketOutputConsumer outputConsumer = null;
        PcapWriter pcapWriter = null;

        long routingFailures = 0;
        long packetsRead = 0;

        try (PcapReader pcapReader = new PcapReader(inputPath)) {

            pcapWriter = new PcapWriter(
                    outputPath,
                    pcapReader.getGlobalHeader());

            outputConsumer =
                    new PacketOutputConsumer(outputQueue, pcapWriter);

            workerManager =
                    new WorkerManager(loadBalancer, fastPath, outputQueue);

            // Start the output thread first
            outputConsumer.start();

            // Start packet-processing workers
            workerManager.startAll();

            RawPacket rawPacket;

            // Read and dispatch every packet
            while ((rawPacket = pcapReader.nextPacket()) != null) {

                packetsRead++;

                try {
                    ParsedPacket parsedPacket =
                            packetParser.parse(rawPacket);

                    loadBalancer.dispatch(rawPacket, parsedPacket);

                } catch (IllegalArgumentException exception) {
                    routingFailures++;
                }
            }

        } finally {

            // Allow workers to finish remaining packets
            if (workerManager != null) {
                workerManager.gracefulStopAll();
                workerManager.awaitTermination();
            }

            // Drain remaining output results
            if (outputConsumer != null) {
                outputConsumer.finish();
                outputConsumer.awaitTermination();
            }

            if (pcapWriter != null) {
                pcapWriter.close();
            }
        }

        return new PipelineStats(
                packetsRead,
                workerManager.getTotalProcessedPackets(),
                workerManager.getTotalFailedPackets(),
                routingFailures,
                outputConsumer.getAllowedPackets(),
                outputConsumer.getBlockedPackets(),
                outputConsumer.getFailedPackets()
        );
    }

    public record PipelineStats(
            long packetsRead,
            long packetsProcessed,
            long workerFailures,
            long routingFailures,
            long allowedPackets,
            long blockedPackets,
            long outputFailures
    ) {}
}
