
package com.deeptrace.extractor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class QUICInitialDecryptor {

    private static final long QUIC_V1 = 0x00000001L;
    private static final long QUIC_V2 = 0x6B3343CFL;

    private static final byte[] V1_SALT = hex(
            "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    );

    private static final byte[] V2_SALT = hex(
            "0dede3def700a6db819381be6e269dcbf9bd2ed9"
    );

    public record InitialKeys(
            byte[] initialSecret,
            byte[] packetKey,
            byte[] iv,
            byte[] headerProtectionKey
    ) {
        public InitialKeys {
            initialSecret = initialSecret.clone();
            packetKey = packetKey.clone();
            iv = iv.clone();
            headerProtectionKey = headerProtectionKey.clone();
        }

        @Override
        public byte[] initialSecret() {
            return initialSecret.clone();
        }

        @Override
        public byte[] packetKey() {
            return packetKey.clone();
        }

        @Override
        public byte[] iv() {
            return iv.clone();
        }

        @Override
        public byte[] headerProtectionKey() {
            return headerProtectionKey.clone();
        }
    }

    public InitialKeys deriveInitialKeys(
            byte[] destinationConnectionId,
            long version,
            boolean client
    ) throws GeneralSecurityException {

        if (destinationConnectionId == null
                || destinationConnectionId.length < 1
                || destinationConnectionId.length > 20) {
            throw new IllegalArgumentException(
                    "DCID must contain between 1 and 20 bytes."
            );
        }

        byte[] salt;
        String keyLabel;
        String ivLabel;
        String hpLabel;

        if (version == QUIC_V1) {
            salt = V1_SALT;
            keyLabel = "quic key";
            ivLabel = "quic iv";
            hpLabel = "quic hp";
        } else if (version == QUIC_V2) {
            salt = V2_SALT;
            keyLabel = "quicv2 key";
            ivLabel = "quicv2 iv";
            hpLabel = "quicv2 hp";
        } else {
            throw new IllegalArgumentException(
                    "Unsupported QUIC version."
            );
        }

        // HKDF-Extract
        byte[] initialSecret = hkdfExtract(
                salt,
                destinationConnectionId
        );

        // Derive client or server Initial secret.
        byte[] trafficSecret = hkdfExpandLabel(
                initialSecret,
                client ? "client in" : "server in",
                32
        );

        // Derive packet protection material.
        byte[] packetKey = hkdfExpandLabel(
                trafficSecret, keyLabel, 16
        );

        byte[] iv = hkdfExpandLabel(
                trafficSecret, ivLabel, 12
        );

        byte[] hp = hkdfExpandLabel(
                trafficSecret, hpLabel, 16
        );

        return new InitialKeys(
                trafficSecret,
                packetKey,
                iv,
                hp
        );
    }

    private static byte[] hkdfExtract(
            byte[] salt,
            byte[] inputKeyMaterial
    ) throws GeneralSecurityException {

        return hmacSha256(salt, inputKeyMaterial);
    }

    private static byte[] hkdfExpandLabel(
            byte[] secret,
            String label,
            int outputLength
    ) throws GeneralSecurityException {

        byte[] fullLabel = (
                "tls13 " + label
        ).getBytes(StandardCharsets.US_ASCII);

        ByteArrayOutputStream info = new ByteArrayOutputStream();

        info.write((outputLength >>> 8) & 0xFF);
        info.write(outputLength & 0xFF);

        info.write(fullLabel.length);
        info.writeBytes(fullLabel);

        info.write(0); // Empty context

        return hkdfExpand(
                secret,
                info.toByteArray(),
                outputLength
        );
    }

    private static byte[] hkdfExpand(
            byte[] prk,
            byte[] info,
            int length
    ) throws GeneralSecurityException {

        byte[] result = new byte[length];
        byte[] previous = new byte[0];

        int offset = 0;
        int counter = 1;

        while (offset < length) {

            ByteArrayOutputStream blockInput =
                    new ByteArrayOutputStream();

            blockInput.writeBytes(previous);
            blockInput.writeBytes(info);
            blockInput.write(counter);

            previous = hmacSha256(
                    prk,
                    blockInput.toByteArray()
            );

            int bytesToCopy = Math.min(
                    previous.length,
                    length - offset
            );

            System.arraycopy(
                    previous, 0,
                    result, offset,
                    bytesToCopy
            );

            offset += bytesToCopy;
            counter++;
        }

        return result;
    }

    private static byte[] hmacSha256(
            byte[] key,
            byte[] data
    ) throws GeneralSecurityException {

        Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(new SecretKeySpec(key, "HmacSHA256"));

        return mac.doFinal(data);
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}
