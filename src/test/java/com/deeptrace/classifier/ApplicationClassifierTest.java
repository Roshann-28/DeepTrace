
package com.deeptrace.classifier;

import com.deeptrace.extractor.ApplicationMetadata;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ApplicationClassifierTest {

    private final ApplicationClassifier classifier =
            new ApplicationClassifier();

    @Test
    void shouldClassifyYouTube() {

        ApplicationMetadata metadata = new ApplicationMetadata(
                "TLS",
                "www.youtube.com",
                "Unknown",
                "TLS_SNI"
        );

        assertEquals(
                AppType.YOUTUBE,
                classifier.classify(metadata)
        );
    }

    @Test
    void shouldClassifyGoogle() {

        ApplicationMetadata metadata = new ApplicationMetadata(
                "TLS",
                "www.google.com",
                "Unknown",
                "TLS_SNI"
        );

        assertEquals(
                AppType.GOOGLE,
                classifier.classify(metadata)
        );
    }

    @Test
    void shouldClassifyInstagram() {

        ApplicationMetadata metadata = new ApplicationMetadata(
                "TLS",
                "www.instagram.com",
                "Unknown",
                "TLS_SNI"
        );

        assertEquals(
                AppType.INSTAGRAM,
                classifier.classify(metadata)
        );
    }

    @Test
    void shouldRecognizeSubdomains() {

        ApplicationMetadata metadata = new ApplicationMetadata(
                "TLS",
                "music.youtube.com",
                "Unknown",
                "TLS_SNI"
        );

        assertEquals(
                AppType.YOUTUBE,
                classifier.classify(metadata)
        );
    }

    @Test
    void shouldNotMatchSimilarButDifferentDomain() {

        ApplicationMetadata metadata = new ApplicationMetadata(
                "TLS",
                "notyoutube.com",
                "Unknown",
                "TLS_SNI"
        );

        assertEquals(
                AppType.TLS,
                classifier.classify(metadata)
        );
    }

    @Test
    void shouldUseProtocolWhenDomainIsUnknown() {

        ApplicationMetadata metadata = new ApplicationMetadata(
                "HTTP",
                "unknown-site.example",
                "Unknown",
                "HTTP_HOST"
        );

        assertEquals(
                AppType.HTTP,
                classifier.classify(metadata)
        );
    }

    @Test
    void shouldReturnUnknownForUnsupportedProtocol() {

        ApplicationMetadata metadata = new ApplicationMetadata(
                "OTHER",
                "unknown-site.example",
                "Unknown",
                "TEST"
        );

        assertEquals(
                AppType.UNKNOWN,
                classifier.classify(metadata)
        );
    }

    @Test
    void shouldReturnUnknownForNullMetadata() {

        assertEquals(
                AppType.UNKNOWN,
                classifier.classify(null)
        );
    }
}
