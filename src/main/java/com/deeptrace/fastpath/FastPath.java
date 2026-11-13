
package com.deeptrace.fastpath;

import com.deeptrace.reader.RawPacket;
import com.deeptrace.parser.PacketParser;
import com.deeptrace.parser.ParsedPacket;
import com.deeptrace.classifier.AppType;
import com.deeptrace.classifier.ApplicationDetectionEngine;
import com.deeptrace.connection.Connection;
import com.deeptrace.connection.ConnectionTracker;
import com.deeptrace.connection.FiveTuple;
import com.deeptrace.rules.RuleDecision;
import com.deeptrace.rules.RuleEvaluator;

public final class FastPath {

    private final PacketParser packetParser;
    private final ApplicationDetectionEngine detectionEngine;
    private final ConnectionTracker connectionTracker;
    private final RuleEvaluator ruleEvaluator;

    public FastPath(
            PacketParser packetParser,
            ApplicationDetectionEngine detectionEngine,
            ConnectionTracker connectionTracker,
            RuleEvaluator ruleEvaluator
    ) {
        if (packetParser == null
                || detectionEngine == null
                || connectionTracker == null
                || ruleEvaluator == null) {
            throw new IllegalArgumentException(
                    "FastPath dependencies cannot be null."
            );
        }

        this.packetParser = packetParser;
        this.detectionEngine = detectionEngine;
        this.connectionTracker = connectionTracker;
        this.ruleEvaluator = ruleEvaluator;
    }

    public record FastPathResult(
            ParsedPacket packet,
            ApplicationDetectionEngine.DetectionResult detection,
            Connection connection,
            RuleDecision decision
    ) {
        public boolean isAllowed() {
            return decision == RuleDecision.ALLOW;
        }

        public boolean isBlocked() {
            return decision == RuleDecision.BLOCK;
        }
    }

    public FastPathResult process(RawPacket rawPacket) {

        if (rawPacket == null) {
            throw new IllegalArgumentException(
                    "Raw packet cannot be null."
            );
        }

        // Step 1: Parse the raw packet
        ParsedPacket parsedPacket = packetParser.parse(rawPacket);

        // Step 2: Detect the application
        ApplicationDetectionEngine.DetectionResult detection =
                detectionEngine.detect(parsedPacket.payload());

        AppType applicationType = detection.applicationType();

        String domain = detection.metadata() == null
                ? null
                : detection.metadata().domain();

        // Step 3: Track TCP and UDP connections
        Connection connection = null;

        boolean trackable =
                ("TCP".equals(parsedPacket.transportProtocol())
                        || "UDP".equals(parsedPacket.transportProtocol()))
                        && parsedPacket.sourcePort() >= 0
                        && parsedPacket.destinationPort() >= 0
                        && !parsedPacket.sourceIp().isBlank()
                        && !parsedPacket.destinationIp().isBlank();

        if (trackable) {

            FiveTuple tuple = FiveTuple.from(parsedPacket);

            long timestamp =
                    rawPacket.header().timestampSeconds();

            connectionTracker.processPacket(
                    parsedPacket,
                    timestamp
            );

            connection = connectionTracker.getConnection(tuple);

            // Update the connection when the application is identified
            if (connection != null
                    && applicationType != AppType.UNKNOWN) {
                connection.setApplicationType(applicationType);
            }
        }

        // Step 4: Evaluate blocking rules
        RuleDecision decision = ruleEvaluator.evaluate(
                parsedPacket,
                applicationType,
                domain
        );

        // Step 5: Return the processing result
        return new FastPathResult(
                parsedPacket,
                detection,
                connection,
                decision
        );
    }
}
