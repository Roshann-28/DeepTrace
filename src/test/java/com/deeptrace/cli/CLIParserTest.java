package com.deeptrace.cli;

import com.deeptrace.classifier.AppType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CLIParserTest {

    @Test
    void shouldParseInputAndOutputPaths() {
        CLIArguments config = CLIParser.parse(
                new String[]{"input.pcap", "output.pcap"}
        );

        assertEquals("input.pcap", config.getInputFile().toString());
        assertEquals("output.pcap", config.getOutputFile().toString());
    }

    @Test
    void shouldUseDefaultConfiguration() {
        CLIArguments config = CLIParser.parse(
                new String[]{"input.pcap", "output.pcap"}
        );

        assertEquals(4, config.getWorkerCount());
        assertEquals(1000, config.getQueueCapacity());
        assertTrue(config.getBlockedIPs().isEmpty());
        assertTrue(config.getBlockedDomains().isEmpty());
        assertTrue(config.getBlockedApplications().isEmpty());
    }

    @Test
    void shouldParseCustomWorkerAndQueueValues() {
        CLIArguments config = CLIParser.parse(
                new String[]{
                        "input.pcap",
                        "output.pcap",
                        "--workers", "8",
                        "--queue-capacity", "500"
                }
        );

        assertEquals(8, config.getWorkerCount());
        assertEquals(500, config.getQueueCapacity());
    }

    @Test
    void shouldParseMultipleBlockingRules() {
        CLIArguments config = CLIParser.parse(
                new String[]{
                        "input.pcap",
                        "output.pcap",
                        "--block-ip", "192.168.1.10",
                        "--block-ip", "10.0.0.5",
                        "--block-domain", "youtube.com",
                        "--block-app", "YOUTUBE"
                }
        );

        assertEquals(2, config.getBlockedIPs().size());
        assertTrue(config.getBlockedIPs().contains("192.168.1.10"));
        assertTrue(config.getBlockedIPs().contains("10.0.0.5"));

        assertEquals(1, config.getBlockedDomains().size());
        assertEquals("youtube.com", config.getBlockedDomains().get(0));

        assertEquals(1, config.getBlockedApplications().size());
        assertEquals(AppType.YOUTUBE, config.getBlockedApplications().get(0));
    }

    @Test
    void shouldAcceptApplicationNameInLowercase() {
        CLIArguments config = CLIParser.parse(
                new String[]{
                        "input.pcap",
                        "output.pcap",
                        "--block-app", "youtube"
                }
        );

        assertEquals(
                AppType.YOUTUBE,
                config.getBlockedApplications().get(0)
        );
    }

    @Test
    void shouldRecognizeHelpOption() {
        CLIArguments config = CLIParser.parse(
                new String[]{"--help"}
        );

        assertTrue(config.isHelpRequested());
    }

    @Test
    void shouldRejectMissingInputAndOutputPaths() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CLIParser.parse(new String[]{"input.pcap"})
        );
    }

    @Test
    void shouldRejectZeroWorkerCount() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CLIParser.parse(
                        new String[]{
                                "input.pcap",
                                "output.pcap",
                                "--workers", "0"
                        }
                )
        );
    }

    @Test
    void shouldRejectNegativeQueueCapacity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CLIParser.parse(
                        new String[]{
                                "input.pcap",
                                "output.pcap",
                                "--queue-capacity", "-10"
                        }
                )
        );
    }

    @Test
    void shouldRejectInvalidNumericValue() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CLIParser.parse(
                        new String[]{
                                "input.pcap",
                                "output.pcap",
                                "--workers", "abc"
                        }
                )
        );
    }

    @Test
    void shouldRejectMissingOptionValue() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CLIParser.parse(
                        new String[]{
                                "input.pcap",
                                "output.pcap",
                                "--workers"
                        }
                )
        );
    }

    @Test
    void shouldRejectUnknownOption() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CLIParser.parse(
                        new String[]{
                                "input.pcap",
                                "output.pcap",
                                "--unknown"
                        }
                )
        );
    }

    @Test
    void shouldRejectUnknownApplication() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CLIParser.parse(
                        new String[]{
                                "input.pcap",
                                "output.pcap",
                                "--block-app", "INVALID_APP"
                        }
                )
        );
    }
}