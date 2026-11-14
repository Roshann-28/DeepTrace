
package com.deeptrace.writer;

import com.deeptrace.reader.PcapReader;
import com.deeptrace.reader.RawPacket;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PcapWriterTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldCopyAllPacketsToNewPcapFile() throws IOException {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("output.pcap");

        int writtenPackets = 0;

        // Read the original PCAP file
        try (PcapReader reader = new PcapReader(inputFile)) {

            // Create writer using original PCAP header
            try (PcapWriter writer = new PcapWriter(
                    outputFile,
                    reader.getGlobalHeader()
            )) {

                RawPacket packet;

                while ((packet = reader.nextPacket()) != null) {

                    writer.writePacket(packet);
                    writtenPackets++;
                }
            }
        }

        // Verify output file exists
        assertTrue(Files.exists(outputFile));

        // Verify output PCAP can be read
        int readPackets = 0;

        try (PcapReader reader = new PcapReader(outputFile)) {

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {
                readPackets++;
            }
        }

        assertEquals(writtenPackets, readPackets);
        assertEquals(77, readPackets);
    }


    @Test
    void shouldPreservePacketDataAndTimestamps() throws IOException {

        Path inputFile = Path.of("test_dpi.pcap");
        Path outputFile = tempDir.resolve("verified_output.pcap");

        // First: Copy the original PCAP
        try (PcapReader reader = new PcapReader(inputFile);
             PcapWriter writer = new PcapWriter(
                     outputFile,
                     reader.getGlobalHeader()
             )) {

            RawPacket packet;

            while ((packet = reader.nextPacket()) != null) {
                writer.writePacket(packet);
            }
        }

        // Second: Compare original and copied packets
        try (PcapReader original = new PcapReader(inputFile);
             PcapReader copied = new PcapReader(outputFile)) {

            RawPacket originalPacket;
            RawPacket copiedPacket;

            int comparedPackets = 0;

            while (true) {

                originalPacket = original.nextPacket();
                copiedPacket = copied.nextPacket();

                // Both files should reach EOF together
                assertEquals(
                        originalPacket == null,
                        copiedPacket == null
                );

                if (originalPacket == null) {
                    break;
                }

                // Compare packet timestamps
                assertEquals(
                        originalPacket.header().timestampSeconds(),
                        copiedPacket.header().timestampSeconds()
                );

                assertEquals(
                        originalPacket.header().timestampFraction(),
                        copiedPacket.header().timestampFraction()
                );

                // Compare packet lengths
                assertEquals(
                        originalPacket.header().capturedLength(),
                        copiedPacket.header().capturedLength()
                );

                assertEquals(
                        originalPacket.header().originalLength(),
                        copiedPacket.header().originalLength()
                );

                // Compare actual packet bytes
                assertArrayEquals(
                        originalPacket.data(),
                        copiedPacket.data()
                );

                comparedPackets++;
            }

            assertEquals(77, comparedPackets);

            System.out.println(
                    "Verified packet integrity: " + comparedPackets
            );
        }
    }

}
