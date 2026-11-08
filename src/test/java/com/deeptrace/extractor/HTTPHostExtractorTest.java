
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class HTTPHostExtractorTest {

    private final HTTPHostExtractor extractor =
            new HTTPHostExtractor();

    @Test
    void shouldExtractHostFromHTTPRequest() {

        String request =
                "GET /index.html HTTP/1.1\r\n" +
                        "Host: example.com\r\n" +
                        "User-Agent: Mozilla/5.0\r\n" +
                        "Accept: text/html\r\n" +
                        "\r\n";

        byte[] payload = request.getBytes(StandardCharsets.US_ASCII);

        ApplicationMetadata result = extractor.extract(payload);

        assertNotNull(result);
        assertEquals("HTTP", result.applicationProtocol());
        assertEquals("example.com", result.domain());
        assertEquals("Unknown", result.applicationName());
        assertEquals("HTTP_HOST", result.detectionSource());
    }

    @Test
    void shouldExtractHostIgnoringHeaderCase() {

        String request =
                "GET / HTTP/1.1\r\n" +
                        "hOsT: Example.COM\r\n" +
                        "\r\n";

        byte[] payload = request.getBytes(StandardCharsets.US_ASCII);

        ApplicationMetadata result = extractor.extract(payload);

        assertNotNull(result);
        assertEquals("example.com", result.domain());
    }

    @Test
    void shouldReturnNullWhenHostHeaderIsMissing() {

        String request =
                "GET /index.html HTTP/1.1\r\n" +
                        "User-Agent: Mozilla/5.0\r\n" +
                        "\r\n";

        byte[] payload = request.getBytes(StandardCharsets.US_ASCII);

        assertNull(extractor.extract(payload));
    }

    @Test
    void shouldReturnNullForNonHTTPPayload() {

        byte[] payload =
                "This is not an HTTP request".getBytes(
                        StandardCharsets.US_ASCII
                );

        assertNull(extractor.extract(payload));
    }

    @Test
    void shouldReturnNullForNullPayload() {

        assertNull(extractor.extract(null));
    }
}
