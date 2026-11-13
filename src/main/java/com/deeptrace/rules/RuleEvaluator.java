
package com.deeptrace.rules;

import com.deeptrace.classifier.AppType;
import com.deeptrace.parser.ParsedPacket;

public final class RuleEvaluator {

    private final RuleManager ruleManager;

    public RuleEvaluator(RuleManager ruleManager) {
        if (ruleManager == null) {
            throw new IllegalArgumentException(
                    "RuleManager cannot be null."
            );
        }

        this.ruleManager = ruleManager;
    }

    public RuleDecision evaluate(
            ParsedPacket packet,
            AppType application,
            String domain
    ) {
        if (packet == null) {
            throw new IllegalArgumentException(
                    "Packet cannot be null."
            );
        }

        // Check source IP.
        if (hasValue(packet.sourceIp())
                && ruleManager.isIPBlocked(packet.sourceIp())) {
            return RuleDecision.BLOCK;
        }

        // Check destination IP.
        if (hasValue(packet.destinationIp())
                && ruleManager.isIPBlocked(packet.destinationIp())) {
            return RuleDecision.BLOCK;
        }

        // Check application.
        if (application != null
                && application != AppType.UNKNOWN
                && ruleManager.isApplicationBlocked(application)) {
            return RuleDecision.BLOCK;
        }

        // Check source port.
        if (isValidPort(packet.sourcePort())
                && ruleManager.isPortBlocked(packet.sourcePort())) {
            return RuleDecision.BLOCK;
        }

        // Check destination port.
        if (isValidPort(packet.destinationPort())
                && ruleManager.isPortBlocked(packet.destinationPort())) {
            return RuleDecision.BLOCK;
        }

        // Check domain, if domain information is available.
        if (hasValue(domain)
                && ruleManager.isDomainBlocked(domain)) {
            return RuleDecision.BLOCK;
        }

        return RuleDecision.ALLOW;
    }

    private boolean hasValue(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isValidPort(int port) {
        return port >= 0 && port <= 65535;
    }
}
