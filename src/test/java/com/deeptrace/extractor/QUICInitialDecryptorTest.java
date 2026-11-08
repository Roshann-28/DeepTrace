
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class QUICInitialDecryptorTest {

    private final QUICInitialDecryptor decryptor =
            new QUICInitialDecryptor();

    private final byte[] dcid = HexFormat.of().parseHex(
            "8394c8f03e515708"
    );

    @Test
    void shouldDeriveQuicV1ClientKeys() throws Exception {

        var keys = decryptor.deriveInitialKeys(
                dcid, 0x00000001L, true
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "c00cf151ca5be075ed0ebfb5c80323c4" +
                                "2d6b7db67881289af4008f1f6c357aea"
                ),
                keys.initialSecret()
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "1f369613dd76d5467730efcbe3b1a22d"
                ),
                keys.packetKey()
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "fa044b2f42a3fd3b46fb255c"
                ),
                keys.iv()
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "9f50449e04a0e810283a1e9933adedd2"
                ),
                keys.headerProtectionKey()
        );
    }

    @Test
    void shouldDeriveQuicV2ClientKeys() throws Exception {

        var keys = decryptor.deriveInitialKeys(
                dcid, 0x6B3343CFL, true
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "14ec9d6eb9fd7af83bf5a668bc17a7e2" +
                                "83766aade7ecd0891f70f9ff7f4bf47b"
                ),
                keys.initialSecret()
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "8b1a0bc121284290a29e0971b5cd045d"
                ),
                keys.packetKey()
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "91f73e2351d8fa91660e909f"
                ),
                keys.iv()
        );

        assertArrayEquals(
                HexFormat.of().parseHex(
                        "45b95e15235d6f45a6b19cbcb0294ba9"
                ),
                keys.headerProtectionKey()
        );
    }

    @Test
    void shouldRejectUnsupportedVersion() {

        assertThrows(
                IllegalArgumentException.class,
                () -> decryptor.deriveInitialKeys(
                        dcid, 2L, true
                )
        );
    }

    @Test
    void shouldRejectInvalidConnectionId() {

        assertThrows(
                IllegalArgumentException.class,
                () -> decryptor.deriveInitialKeys(
                        new byte[0], 1L, true
                )
        );
    }
}
