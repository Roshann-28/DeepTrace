
package com.deeptrace.rules;

public record RuleStatistics(
        int blockedIPCount,
        int blockedApplicationCount,
        int blockedPortCount,
        int blockedDomainCount
) {

    public int totalRuleCount() {
        return blockedIPCount
                + blockedApplicationCount
                + blockedPortCount
                + blockedDomainCount;
    }
}
