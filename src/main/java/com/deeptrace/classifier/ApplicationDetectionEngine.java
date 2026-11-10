
package com.deeptrace.classifier;

import com.deeptrace.extractor.ApplicationMetadata;
import com.deeptrace.extractor.DNSExtractor;
import com.deeptrace.extractor.HTTPHostExtractor;
import com.deeptrace.extractor.QUICExtractor;
import com.deeptrace.extractor.TLSExtractor;

public final class ApplicationDetectionEngine {

    private final DNSExtractor dnsExtractor = new DNSExtractor();
    private final HTTPHostExtractor httpExtractor =
            new HTTPHostExtractor();
    private final TLSExtractor tlsExtractor = new TLSExtractor();
    private final QUICExtractor quicExtractor = new QUICExtractor();

    private final ApplicationClassifier classifier =
            new ApplicationClassifier();

    public record DetectionResult(
            ApplicationMetadata metadata,
            AppType applicationType
    ) {
        public boolean isIdentified() {
            return applicationType != AppType.UNKNOWN;
        }
    }

    public DetectionResult detect(byte[] payload) {

        if (payload == null || payload.length == 0) {
            return unknownResult();
        }

        // 1. Try to identify a DNS query.
        ApplicationMetadata metadata = dnsExtractor.extract(payload);

        if (metadata != null) {
            return createResult(metadata);
        }

        // 2. Try to identify an HTTP Host header.
        metadata = httpExtractor.extract(payload);

        if (metadata != null) {
            return createResult(metadata);
        }

        // 3. Try to extract TLS Server Name Indication.
        metadata = tlsExtractor.extract(payload);

        if (metadata != null) {
            return createResult(metadata);
        }

        // 4. Check whether this is a QUIC Initial packet.
        if (quicExtractor.isQuicInitial(payload)) {

            metadata = new ApplicationMetadata(
                    "QUIC",
                    "unknown",
                    "Unknown",
                    "QUIC_INITIAL"
            );

            return createResult(metadata);
        }

        return unknownResult();
    }

    private DetectionResult createResult(
            ApplicationMetadata metadata
    ) {
        AppType applicationType = classifier.classify(metadata);

        return new DetectionResult(
                metadata,
                applicationType
        );
    }

    private DetectionResult unknownResult() {
        return new DetectionResult(
                null,
                AppType.UNKNOWN
        );
    }
}
