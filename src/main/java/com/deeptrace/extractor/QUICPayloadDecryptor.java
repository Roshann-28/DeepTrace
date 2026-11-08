
package com.deeptrace.extractor;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class QUICPayloadDecryptor {

    private static final int KEY_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = 16;

    private static final long MAX_PACKET_NUMBER = (1L << 62) - 1;

    public byte[] decrypt(
            byte[] key,
            byte[] iv,
            long packetNumber,
            byte[] associatedData,
            byte[] ciphertext
    ) throws GeneralSecurityException {

        validateInputs(key, iv, packetNumber, associatedData, ciphertext);

        // Create a packet-specific nonce.
        byte[] nonce = createNonce(iv, packetNumber);

        // Configure AES-GCM.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        SecretKeySpec secretKey =
                new SecretKeySpec(key, "AES");

        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        // Authenticate the unprotected QUIC header.
        cipher.updateAAD(associatedData);

        // Decrypt and verify the authentication tag.
        // An invalid tag causes an AEADBadTagException.
        return cipher.doFinal(ciphertext);
    }

    private byte[] createNonce(byte[] iv, long packetNumber) {

        byte[] nonce = Arrays.copyOf(iv, iv.length);

        // XOR the packet number into the last 8 bytes of the IV.
        for (int i = 0; i < Long.BYTES; i++) {

            nonce[nonce.length - 1 - i] ^=
                    (byte) (packetNumber >>> (i * 8));
        }

        return nonce;
    }

    private void validateInputs(
            byte[] key,
            byte[] iv,
            long packetNumber,
            byte[] associatedData,
            byte[] ciphertext
    ) {

        if (key == null || key.length != KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "AES-128 key must contain exactly 16 bytes."
            );
        }

        if (iv == null || iv.length != IV_LENGTH) {
            throw new IllegalArgumentException(
                    "QUIC IV must contain exactly 12 bytes."
            );
        }

        if (packetNumber < 0 || packetNumber > MAX_PACKET_NUMBER) {
            throw new IllegalArgumentException(
                    "Invalid QUIC packet number."
            );
        }

        if (associatedData == null) {
            throw new IllegalArgumentException(
                    "Associated data cannot be null."
            );
        }

        if (ciphertext == null ||
                ciphertext.length < TAG_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "Ciphertext must contain an authentication tag."
            );
        }
    }
}
