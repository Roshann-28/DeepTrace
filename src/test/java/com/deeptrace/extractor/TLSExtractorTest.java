
package com.deeptrace.extractor;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class TLSExtractorTest {

    @Test
    void shouldExtractDomainFromTLSClientHello() throws IOException {

        // Arrange: Create a TLS ClientHello containing google.com
        byte[] payload = createTLSClientHello("google.com");

        TLSExtractor extractor = new TLSExtractor();

        // Act: Extract application metadata
        ApplicationMetadata result = extractor.extract(payload);

        // Assert: Verify extracted information
        assertNotNull(result, "TLS metadata should not be null");

        assertEquals("TLS", result.applicationProtocol());
        assertEquals("google.com", result.domain());
        assertEquals("Unknown", result.applicationName());
        assertEquals("TLS_SNI", result.detectionSource());
    }

    @Test
    void shouldReturnNullForNonTLSPayload() {

        TLSExtractor extractor = new TLSExtractor();

        byte[] payload = {
                0x45, 0x00, 0x00, 0x20,
                0x01, 0x02, 0x03, 0x04
        };

        ApplicationMetadata result = extractor.extract(payload);

        assertNull(result);
    }

    @Test
    void shouldReturnNullForNullPayload() {

        TLSExtractor extractor = new TLSExtractor();

        ApplicationMetadata result = extractor.extract(null);

        assertNull(result);
    }

    private byte[] createTLSClientHello(String domain)
            throws IOException {

        ByteArrayOutputStream serverName = new ByteArrayOutputStream();

        byte[] domainBytes = domain.getBytes(
                java.nio.charset.StandardCharsets.US_ASCII
        );

        // Server name entry
        serverName.write(0x00);
        writeUnsignedShort(serverName, domainBytes.length);
        serverName.write(domainBytes);

        // Server name list
        ByteArrayOutputStream serverNameList = new ByteArrayOutputStream();

        writeUnsignedShort(serverNameList, serverName.size());
        serverNameList.write(serverName.toByteArray());

        // SNI extension
        ByteArrayOutputStream sniExtension = new ByteArrayOutputStream();

        writeUnsignedShort(sniExtension, 0x0000);
        writeUnsignedShort(sniExtension, serverNameList.size());
        sniExtension.write(serverNameList.toByteArray());

        // Extensions section
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();

        extensions.write(sniExtension.toByteArray());

        // ClientHello body
        ByteArrayOutputStream clientHello = new ByteArrayOutputStream();

        // TLS version
        clientHello.write(0x03);
        clientHello.write(0x03);

        // 32-byte random
        clientHello.write(new byte[32]);

        // Empty session ID
        clientHello.write(0x00);

        // Cipher suites: TLS_AES_128_GCM_SHA256
        writeUnsignedShort(clientHello, 2);
        clientHello.write(0x13);
        clientHello.write(0x01);

        // Compression methods
        clientHello.write(0x01);
        clientHello.write(0x00);

        // Extensions length and extensions
        writeUnsignedShort(clientHello, extensions.size());
        clientHello.write(extensions.toByteArray());

        // Handshake message
        ByteArrayOutputStream handshake = new ByteArrayOutputStream();

        handshake.write(0x01);

        int handshakeLength = clientHello.size();

        handshake.write((handshakeLength >> 16) & 0xFF);
        handshake.write((handshakeLength >> 8) & 0xFF);
        handshake.write(handshakeLength & 0xFF);

        handshake.write(clientHello.toByteArray());

        // TLS record
        ByteArrayOutputStream tlsRecord = new ByteArrayOutputStream();

        tlsRecord.write(0x16);
        tlsRecord.write(0x03);
        tlsRecord.write(0x01);

        writeUnsignedShort(tlsRecord, handshake.size());

        tlsRecord.write(handshake.toByteArray());

        return tlsRecord.toByteArray();
    }

    private void writeUnsignedShort(
            ByteArrayOutputStream output,
            int value
    ) {
        output.write((value >> 8) & 0xFF);
        output.write(value & 0xFF);
    }
}
