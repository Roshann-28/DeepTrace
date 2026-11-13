
package com.deeptrace.rules;

import org.junit.jupiter.api.Test;
import com.deeptrace.classifier.AppType;

import static org.junit.jupiter.api.Assertions.*;

class RuleManagerTest {

    private final RuleManager ruleManager = new RuleManager();

    @Test
    void shouldBlockIP() {
        ruleManager.blockIP("192.168.1.10");

        assertTrue(ruleManager.isIPBlocked("192.168.1.10"));
    }

    @Test
    void shouldUnblockIP() {
        ruleManager.blockIP("192.168.1.10");

        ruleManager.unblockIP("192.168.1.10");

        assertFalse(ruleManager.isIPBlocked("192.168.1.10"));
    }

    @Test
    void shouldAvoidDuplicateIPs() {
        ruleManager.blockIP("192.168.1.10");
        ruleManager.blockIP("192.168.1.10");

        assertEquals(1, ruleManager.getBlockedIPCount());
    }

    @Test
    void shouldReturnAllBlockedIPs() {
        ruleManager.blockIP("192.168.1.10");
        ruleManager.blockIP("142.250.183.14");

        assertEquals(2, ruleManager.getBlockedIPs().size());
    }

    @Test
    void shouldNormalizeIPAddresses() {
        ruleManager.blockIP("192.168.001.010");

        assertTrue(ruleManager.isIPBlocked("192.168.1.10"));
    }

    @Test
    void shouldRejectInvalidIP() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ruleManager.blockIP("300.168.1.10")
        );
    }

    @Test
    void shouldRejectNullIP() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ruleManager.blockIP(null)
        );
    }


    @Test
    void shouldBlockApplication() {
        ruleManager.blockApplication(AppType.YOUTUBE);

        assertTrue(
                ruleManager.isApplicationBlocked(AppType.YOUTUBE)
        );
    }

    @Test
    void shouldUnblockApplication() {
        ruleManager.blockApplication(AppType.YOUTUBE);

        ruleManager.unblockApplication(AppType.YOUTUBE);

        assertFalse(
                ruleManager.isApplicationBlocked(AppType.YOUTUBE)
        );
    }

    @Test
    void shouldRejectUnknownApplication() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ruleManager.blockApplication(AppType.UNKNOWN)
        );
    }

    @Test
    void shouldReturnBlockedApplications() {
        ruleManager.blockApplication(AppType.YOUTUBE);
        ruleManager.blockApplication(AppType.INSTAGRAM);

        assertEquals(2, ruleManager.getBlockedApplicationCount());
        assertEquals(2, ruleManager.getBlockedApplications().size());
    }

    @Test
    void shouldBlockPort() {
        ruleManager.blockPort(443);

        assertTrue(ruleManager.isPortBlocked(443));
    }

    @Test
    void shouldUnblockPort() {
        ruleManager.blockPort(443);

        ruleManager.unblockPort(443);

        assertFalse(ruleManager.isPortBlocked(443));
    }

    @Test
    void shouldRejectInvalidPort() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ruleManager.blockPort(70000)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> ruleManager.blockPort(-1)
        );
    }

    @Test
    void shouldReturnBlockedPorts() {
        ruleManager.blockPort(443);
        ruleManager.blockPort(53);

        assertEquals(2, ruleManager.getBlockedPortCount());
        assertEquals(2, ruleManager.getBlockedPorts().size());
    }


    @Test
    void shouldBlockExactDomain() {
        ruleManager.blockDomain("youtube.com");

        assertTrue(ruleManager.isDomainBlocked("youtube.com"));
    }

    @Test
    void shouldBlockSubdomains() {
        ruleManager.blockDomain("youtube.com");

        assertTrue(ruleManager.isDomainBlocked("www.youtube.com"));
        assertTrue(ruleManager.isDomainBlocked("music.youtube.com"));
    }

    @Test
    void shouldNotBlockUnrelatedDomain() {
        ruleManager.blockDomain("youtube.com");

        assertFalse(ruleManager.isDomainBlocked("notyoutube.com"));
    }

    @Test
    void shouldSupportWildcardDomain() {
        ruleManager.blockDomain("*.facebook.com");

        assertTrue(ruleManager.isDomainBlocked("www.facebook.com"));
        assertTrue(ruleManager.isDomainBlocked("m.facebook.com"));
        assertFalse(ruleManager.isDomainBlocked("facebook.com"));
    }

    @Test
    void shouldUnblockDomain() {
        ruleManager.blockDomain("youtube.com");

        ruleManager.unblockDomain("youtube.com");

        assertFalse(ruleManager.isDomainBlocked("youtube.com"));
        assertFalse(ruleManager.isDomainBlocked("www.youtube.com"));
    }

    @Test
    void shouldNormalizeDomain() {
        ruleManager.blockDomain("YOUTUBE.COM.");

        assertTrue(ruleManager.isDomainBlocked("www.youtube.com"));
    }

    @Test
    void shouldReturnBlockedDomains() {
        ruleManager.blockDomain("youtube.com");
        ruleManager.blockDomain("*.facebook.com");

        assertEquals(2, ruleManager.getBlockedDomainCount());
        assertEquals(2, ruleManager.getBlockedDomains().size());
    }

    @Test
    void shouldRejectInvalidDomain() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ruleManager.blockDomain("invalid domain")
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> ruleManager.blockDomain(null)
        );
    }


    @Test
    void shouldReturnRuleStatistics() {
        ruleManager.blockIP("192.168.1.10");
        ruleManager.blockIP("192.168.1.20");

        ruleManager.blockApplication(AppType.YOUTUBE);
        ruleManager.blockApplication(AppType.INSTAGRAM);

        ruleManager.blockPort(443);

        ruleManager.blockDomain("youtube.com");
        ruleManager.blockDomain("facebook.com");

        RuleStatistics statistics = ruleManager.getRuleStatistics();

        assertEquals(2, statistics.blockedIPCount());
        assertEquals(2, statistics.blockedApplicationCount());
        assertEquals(1, statistics.blockedPortCount());
        assertEquals(2, statistics.blockedDomainCount());
        assertEquals(7, statistics.totalRuleCount());
    }

    @Test
    void shouldReturnTotalRuleCount() {
        ruleManager.blockIP("192.168.1.10");
        ruleManager.blockApplication(AppType.YOUTUBE);
        ruleManager.blockPort(443);
        ruleManager.blockDomain("youtube.com");

        assertEquals(4, ruleManager.getTotalRuleCount());
    }

    @Test
    void shouldClearAllRules() {
        ruleManager.blockIP("192.168.1.10");
        ruleManager.blockApplication(AppType.YOUTUBE);
        ruleManager.blockPort(443);
        ruleManager.blockDomain("youtube.com");

        ruleManager.clearAllRules();

        assertEquals(0, ruleManager.getTotalRuleCount());

        assertFalse(ruleManager.isIPBlocked("192.168.1.10"));
        assertFalse(ruleManager.isApplicationBlocked(AppType.YOUTUBE));
        assertFalse(ruleManager.isPortBlocked(443));
        assertFalse(ruleManager.isDomainBlocked("youtube.com"));
    }

    @Test
    void shouldReturnZeroStatisticsWhenNoRulesExist() {
        RuleStatistics statistics = ruleManager.getRuleStatistics();

        assertEquals(0, statistics.blockedIPCount());
        assertEquals(0, statistics.blockedApplicationCount());
        assertEquals(0, statistics.blockedPortCount());
        assertEquals(0, statistics.blockedDomainCount());
        assertEquals(0, statistics.totalRuleCount());
    }

    @Test
    void shouldKeepRulesAfterReadingStatistics() {
        ruleManager.blockIP("192.168.1.10");

        ruleManager.getRuleStatistics();

        assertTrue(ruleManager.isIPBlocked("192.168.1.10"));
        assertEquals(1, ruleManager.getTotalRuleCount());
    }



}
