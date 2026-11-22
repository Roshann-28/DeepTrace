package com.deeptrace;

import com.deeptrace.cli.CLIArguments;
import com.deeptrace.cli.CLIParser;
import com.deeptrace.classifier.AppType;
import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.fastpath.FastPath;
import com.deeptrace.pipeline.PacketPipeline;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.rules.RuleEvaluator;
import com.deeptrace.rules.RuleManager;

import java.io.IOException;

public class Main {

    public static void main(String[] args) {

        try {

            // Step 1: Parse CLI arguments
            CLIArguments config = CLIParser.parse(args);

            // Step 2: Display help if requested
            if (config.isHelpRequested()) {
                printUsage();
                return;
            }

            // Step 3: Configure blocking rules
            RuleManager ruleManager = new RuleManager();

            for (String ip : config.getBlockedIPs()) {
                ruleManager.blockIP(ip);
            }

            for (String domain : config.getBlockedDomains()) {
                ruleManager.blockDomain(domain);
            }

            for (AppType app : config.getBlockedApplications()) {
                ruleManager.blockApplication(app);
            }

            // Step 4: Create FastPath dependencies
            FastPath fastPath = new FastPath(
                    new PacketParser(),
                    new ApplicationDetectionEngine(),
                    new ConnectionTracker(),
                    new RuleEvaluator(ruleManager)
            );

            // Step 5: Create the packet pipeline
            PacketPipeline pipeline = new PacketPipeline(
                    config.getInputFile(),
                    config.getOutputFile(),
                    config.getWorkerCount(),
                    config.getQueueCapacity(),
                    fastPath
            );

            // Step 6: Run DeepTrace
            System.out.println("========================================");
            System.out.println("              DEEPTRACE");
            System.out.println("========================================");
            System.out.println("Input PCAP  : " + config.getInputFile());
            System.out.println("Output PCAP : " + config.getOutputFile());
            System.out.println("Workers     : " + config.getWorkerCount());
            System.out.println("Queue Size  : " + config.getQueueCapacity());
            System.out.println("----------------------------------------");

            PacketPipeline.PipelineStats stats = pipeline.run();

            // Step 7: Display final statistics
            System.out.println("\n========================================");
            System.out.println("          DEEPTRACE SUMMARY");
            System.out.println("========================================");

            System.out.println("Packets read       : " + stats.packetsRead());
            System.out.println("Packets processed   : " + stats.packetsProcessed());
            System.out.println("Allowed packets    : " + stats.allowedPackets());
            System.out.println("Blocked packets   : " + stats.blockedPackets());
            System.out.println("Worker failures   : " + stats.workerFailures());
            System.out.println("Routing failures  : " + stats.routingFailures());
            System.out.println("Output failures   : " + stats.outputFailures());

            System.out.println("----------------------------------------");
            System.out.println("Filtered PCAP saved to: " + config.getOutputFile());
            System.out.println("========================================");

        } catch (InterruptedException exception) {

            Thread.currentThread().interrupt();

            System.err.println("DeepTrace interrupted.");

        } catch (IOException | IllegalArgumentException exception) {

            System.err.println("DeepTrace error: " + exception.getMessage());
            System.err.println("Use --help to see available options.");

        }
    }

    private static void printUsage() {

        System.out.println("""
                ========================================
                         DEEPTRACE CLI
                ========================================

                Usage:
                  java -jar DeepTrace.jar <input.pcap> <output.pcap> [options]

                Options:
                  --workers <number>          Number of worker threads
                  --queue-capacity <num>    Worker queue capacity
                  --block-ip <ip>           Block an IP address
                  --block-domain <domain>   Block a domain
                  --block-app <app>         Block an application
                  --help, -h                Display this help

                Examples:
                  java -jar DeepTrace.jar input.pcap output.pcap

                  java -jar DeepTrace.jar input.pcap output.pcap --workers 8

                  java -jar DeepTrace.jar input.pcap output.pcap --block-ip 192.168.1.10

                  java -jar DeepTrace.jar input.pcap output.pcap --block-domain youtube.com

                  java -jar DeepTrace.jar input.pcap output.pcap --block-app YOUTUBE

                ========================================
                """);
    }
}