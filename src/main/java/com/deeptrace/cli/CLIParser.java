package com.deeptrace.cli;

import com.deeptrace.classifier.AppType;

import java.nio.file.Path;
import java.util.Locale;

public final class CLIParser {

    private CLIParser() {
    }

    public static CLIArguments parse(String[] args) {

        CLIArguments config = new CLIArguments();

        // Handle help before requiring input/output paths
        for (String arg : args) {
            if ("--help".equals(arg) || "-h".equals(arg)) {
                config.setHelpRequested(true);
                return config;
            }
        }

        if (args.length < 2) {
            throw new IllegalArgumentException(
                    "Input and output PCAP paths are required."
            );
        }

        config.setInputFile(Path.of(args[0]));
        config.setOutputFile(Path.of(args[1]));

        int index = 2;

        while (index < args.length) {

            String option = args[index];

            switch (option) {

                case "--workers" -> {
                    String value = requireValue(args, index, option);
                    int workers = parsePositiveInteger(value, option);
                    config.setWorkerCount(workers);
                    index += 2;
                }

                case "--queue-capacity" -> {
                    String value = requireValue(args, index, option);
                    int capacity = parsePositiveInteger(value, option);
                    config.setQueueCapacity(capacity);
                    index += 2;
                }

                case "--block-ip" -> {
                    String value = requireValue(args, index, option);
                    config.getBlockedIPs().add(value);
                    index += 2;
                }

                case "--block-domain" -> {
                    String value = requireValue(args, index, option);
                    config.getBlockedDomains().add(value);
                    index += 2;
                }

                case "--block-app" -> {
                    String value = requireValue(args, index, option);

                    try {
                        AppType appType = AppType.valueOf(
                                value.toUpperCase(Locale.ROOT)
                        );

                        config.getBlockedApplications().add(appType);

                    } catch (IllegalArgumentException exception) {
                        throw new IllegalArgumentException(
                                "Unknown application: " + value
                        );
                    }

                    index += 2;
                }

                default -> throw new IllegalArgumentException(
                        "Unknown option: " + option
                );
            }
        }

        return config;
    }

    private static String requireValue(
            String[] args,
            int index,
            String option
    ) {

        if (index + 1 >= args.length) {
            throw new IllegalArgumentException(
                    "Missing value for option: " + option
            );
        }

        return args[index + 1];
    }

    private static int parsePositiveInteger(
            String value,
            String option
    ) {

        try {
            int number = Integer.parseInt(value);

            if (number <= 0) {
                throw new IllegalArgumentException(
                        option + " must be greater than zero."
                );
            }

            return number;

        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                    "Invalid number for " + option + ": " + value
            );
        }
    }
}