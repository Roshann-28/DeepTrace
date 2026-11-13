
package com.deeptrace.rules;

import com.deeptrace.classifier.AppType;
import com.deeptrace.parser.ParsedPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RuleEvaluatorTest {

    private RuleManager ruleManager;
    private RuleEvaluator evaluator;

    @BeforeEach
    void setUp() {
        ruleManager = new RuleManager();
        evaluator = new RuleEvaluator(ruleManager);
    }

    @Test
    void shouldAllowPacketWhenNoRulesMatch() {
        ParsedPacket packet = createPacket();

        RuleDecision decision = evaluator.evaluate(
                packet, AppType.YOUTUBE, "www.youtube.com"
        );

        assertEquals(RuleDecision.ALLOW, decision);
    }

    @Test
    void shouldBlockPacketWhenSourceIPIsBlocked() {
        ruleManager.blockIP("192.168.1.5");

        RuleDecision decision = evaluator.evaluate(
                createPacket(), AppType.YOUTUBE, "www.youtube.com"
        );

        assertEquals(RuleDecision.BLOCK, decision);
    }

    @Test
    void shouldBlockPacketWhenDestinationIPIsBlocked() {
        ruleManager.blockIP("142.250.183.14");

        RuleDecision decision = evaluator.evaluate(
                createPacket(), AppType.YOUTUBE, "www.youtube.com"
        );

        assertEquals(RuleDecision.BLOCK, decision);
    }

    @Test
    void shouldBlockPacketWhenApplicationIsBlocked() {
        ruleManager.blockApplication(AppType.YOUTUBE);

        RuleDecision decision = evaluator.evaluate(
                createPacket(), AppType.YOUTUBE, "www.youtube.com"
        );

        assertEquals(RuleDecision.BLOCK, decision);
    }

    @Test
    void shouldBlockPacketWhenPortIsBlocked() {
        ruleManager.blockPort(443);

        RuleDecision decision = evaluator.evaluate(
                createPacket(), AppType.YOUTUBE, "www.youtube.com"
        );

        assertEquals(RuleDecision.BLOCK, decision);
    }

    @Test
    void shouldBlockPacketWhenDomainIsBlocked() {
        ruleManager.blockDomain("youtube.com");

        RuleDecision decision = evaluator.evaluate(
                createPacket(), AppType.YOUTUBE, "www.youtube.com"
        );

        assertEquals(RuleDecision.BLOCK, decision);
    }

    @Test
    void shouldAllowPacketWhenApplicationAndDomainAreUnknown() {
        RuleDecision decision = evaluator.evaluate(
                createPacket(), AppType.UNKNOWN, null
        );

        assertEquals(RuleDecision.ALLOW, decision);
    }

    @Test
    void shouldRejectNullPacket() {
        assertThrows(
                IllegalArgumentException.class,
                () -> evaluator.evaluate(
                        null, AppType.YOUTUBE, "youtube.com"
                )
        );
    }

    private ParsedPacket createPacket() {
        return new ParsedPacket(
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
                0x0800,
                "192.168.1.5",
                "142.250.183.14",
                64,
                6,
                "TCP",
                50001,
                443,
                0,
                14,
                20,
                20,
                new byte[0]
        );
    }
}
