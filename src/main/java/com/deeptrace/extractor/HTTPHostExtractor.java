
package com.deeptrace.extractor;

import java.nio.charset.StandardCharsets;

public final class HTTPHostExtractor {

    public ApplicationMetadata extract(byte[] payload) {

        if (payload == null || payload.length == 0) {
            return null;
        }

        String request = new String(
                payload,
                StandardCharsets.US_ASCII
        );

        // Check whether this looks like an HTTP request.
        int firstLineEnd = request.indexOf("\r\n");

        if (firstLineEnd == -1) {
            return null;
        }

        String requestLine = request.substring(0, firstLineEnd);

        if (!isValidRequestLine(requestLine)) {
            return null;
        }

        // Read HTTP headers.
        String[] lines = request.substring(firstLineEnd + 2)
                .split("\r\n");

        for (String line : lines) {

            // End of HTTP headers.
            if (line.isEmpty()) {
                break;
            }

            int separator = line.indexOf(':');

            if (separator <= 0) {
                continue;
            }

            String headerName = line.substring(0, separator)
                    .trim();

            String headerValue = line.substring(separator + 1)
                    .trim();

            if (headerName.equalsIgnoreCase("Host")) {

                String domain = normalizeHost(headerValue);

                if (domain == null) {
                    return null;
                }

                return new ApplicationMetadata(
                        "HTTP",
                        domain,
                        "Unknown",
                        "HTTP_HOST"
                );
            }
        }

        return null;
    }

    private boolean isValidRequestLine(String requestLine) {

        String[] parts = requestLine.split(" ", 3);

        if (parts.length != 3) {
            return false;
        }

        String method = parts[0];

        String version = parts[2];

        boolean validMethod = switch (method) {
            case "GET", "POST", "PUT", "DELETE",
                 "HEAD", "OPTIONS", "PATCH", "CONNECT",
                 "TRACE" -> true;
            default -> false;
        };

        boolean validVersion =
                version.equals("HTTP/1.0")
                        || version.equals("HTTP/1.1");

        return validMethod && validVersion;
    }

    private String normalizeHost(String host) {

        if (host == null || host.isBlank()) {
            return null;
        }

        host = host.trim().toLowerCase();

        // Remove an optional port from ordinary hostnames.
        int firstColon = host.indexOf(':');
        int lastColon = host.lastIndexOf(':');

        if (firstColon > 0 && firstColon == lastColon) {
            host = host.substring(0, firstColon);
        }

        if (host.isBlank()) {
            return null;
        }

        return host;
    }
}
