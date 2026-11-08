
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class QUICPayloadDecryptorTest {

    private final QUICPayloadDecryptor decryptor =
            new QUICPayloadDecryptor();

    @Test
    void shouldDecryptValidPayload() throws Exception {

        byte[] key = new byte[16];
        byte[] iv = new byte[12];

        Arrays.fill(key, (byte) 0x11);
        Arrays.fill(iv, (byte) 0x22);

        long packetNumber = 5;

        byte[] header = {
                (byte) 0x40, 0x01, 0x02, 0x03
        };

        byte[] plaintext = "DeepTrace QUIC payload".getBytes();

        byte[] ciphertext = encryptForTest(
                key, iv, packetNumber, header, plaintext
        );

        byte[] decrypted = decryptor.decrypt(
                key, iv, packetNumber, header, ciphertext
        );

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldRejectTamperedCiphertext() throws Exception {

        byte[] key = new byte[16];
        byte[] iv = new byte[12];

        Arrays.fill(key, (byte) 0x11);
        Arrays.fill(iv, (byte) 0x22);

        long packetNumber = 5;

        byte[] header = {0x40, 0x01, 0x02, 0x03};
        byte[] plaintext = "Secure payload".getBytes();

        byte[] ciphertext = encryptForTest(
                key, iv, packetNumber, header, plaintext
        );

        // Change one byte in the encrypted payload.
        ciphertext[0] ^= 0x01;

        assertThrows(
                AEADBadTagException.class,
                () -> decryptor.decrypt(
                        key, iv, packetNumber, header, ciphertext
                )
        );
    }

    @Test
    void shouldRejectTamperedAssociatedData() throws Exception {

        byte[] key = new byte[16];
        byte[] iv = new byte[12];

        Arrays.fill(key, (byte) 0x11);
        Arrays.fill(iv, (byte) 0x22);

        long packetNumber = 5;

        byte[] header = {0x40, 0x01, 0x02, 0x03};
        byte[] plaintext = "Secure payload".getBytes();

        byte[] ciphertext = encryptForTest(
                key, iv, packetNumber, header, plaintext
        );

        // Change the authenticated header.
        header[0] ^= 0x01;

        assertThrows(
                AEADBadTagException.class,
                () -> decryptor.decrypt(
                        key, iv, packetNumber, header, ciphertext
                )
        );
    }

    @Test
    void shouldRejectInvalidKeyLength() {

        byte[] invalidKey = new byte[8];
        byte[] iv = new byte[12];
        byte[] header = {0x40};
        byte[] ciphertext = new byte[16];

        assertThrows(
                IllegalArgumentException.class,
                () -> decryptor.decrypt(
                        invalidKey, iv, 1, header, ciphertext
                )
        );
    }

    private byte[] encryptForTest(
            byte[] key,
            byte[] iv,
            long packetNumber,
            byte[] header,
            byte[] plaintext
    ) throws GeneralSecurityException {

        byte[] nonce = Arrays.copyOf(iv, iv.length);

        for (int i = 0; i < Long.BYTES; i++) {
            nonce[nonce.length - 1 - i] ^=
                    (byte) (packetNumber >>> (i * 8));
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce)
        );

        cipher.updateAAD(header);

        return cipher.doFinal(plaintext);
    }
}
