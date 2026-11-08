
package com.deeptrace.extractor;

public record ApplicationMetadata(
        String applicationProtocol,
        String domain,
        String applicationName,
        String detectionSource
) {

    public ApplicationMetadata {
        if (applicationProtocol == null || applicationProtocol.isBlank()) {
            throw new IllegalArgumentException(
                    "Application protocol cannot be empty."
            );
        }

        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException(
                    "Domain cannot be empty."
            );
        }

        if (applicationName == null || applicationName.isBlank()) {
            applicationName = "Unknown";
        }

        if (detectionSource == null || detectionSource.isBlank()) {
            throw new IllegalArgumentException(
                    "Detection source cannot be empty."
            );
        }

        domain = domain.trim().toLowerCase();
        applicationProtocol = applicationProtocol.trim().toUpperCase();
        applicationName = applicationName.trim();
        detectionSource = detectionSource.trim().toUpperCase();
    }
}
