
package com.deeptrace.parser;

import com.deeptrace.reader.RawPacket;

public final class PacketParser {

    private static final int ETHERNET_HEADER_LENGTH = 14;

    private static final int ETHERTYPE_IPV4 = 0x0800;

    private static final int ETHERTYPE_VLAN = 0x8100;
    private static final int ETHERTYPE_QINQ = 0x88A8;
    private static final int ETHERTYPE_VLAN_9100 = 0x9100;

    private static final int IP_PROTOCOL_TCP = 6;
    private static final int IP_PROTOCOL_UDP = 17;

    public ParsedPacket parse(RawPacket rawPacket) {

        if (rawPacket == null) {
            throw new IllegalArgumentException("Raw packet cannot be null.");
        }

        byte[] data = rawPacket.data();

        // Step 1: Validate Ethernet header.
        if (data.length < ETHERNET_HEADER_LENGTH) {
            throw new IllegalArgumentException("Incomplete Ethernet header.");
        }

        String destinationMac = readMacAddress(data, 0);
        String sourceMac = readMacAddress(data, 6);

        int etherType = readUnsignedShort(data, 12);
        int ethernetHeaderLength = ETHERNET_HEADER_LENGTH;

        // Step 2: Handle VLAN tags.
        while (isVlan(etherType)) {

            if (data.length < ethernetHeaderLength + 4) {
                throw new IllegalArgumentException("Incomplete VLAN header.");
            }

            etherType = readUnsignedShort(data, ethernetHeaderLength + 2);
            ethernetHeaderLength += 4;
        }

        // Step 3: Handle non-IPv4 Ethernet packets.
        if (etherType != ETHERTYPE_IPV4) {
            byte[] payload = copyBytes(
                    data,
                    ethernetHeaderLength,
                    data.length
            );

            return new ParsedPacket(
                    sourceMac,
                    destinationMac,
                    etherType,
                    "",
                    "",
                    -1,
                    -1,
                    "OTHER",
                    -1,
                    -1,
                    0,
                    ethernetHeaderLength,
                    0,
                    0,
                    payload
            );
        }

        // Step 4: Validate IPv4 minimum header.
        int ipOffset = ethernetHeaderLength;

        if (data.length < ipOffset + 20) {
            throw new IllegalArgumentException("Incomplete IPv4 header.");
        }

        int versionAndIhl = data[ipOffset] & 0xFF;

        int version = (versionAndIhl >> 4) & 0x0F;
        int ipHeaderLength = (versionAndIhl & 0x0F) * 4;

        if (version != 4) {
            throw new IllegalArgumentException("Invalid IPv4 version.");
        }

        if (ipHeaderLength < 20) {
            throw new IllegalArgumentException("Invalid IPv4 header length.");
        }

        if (data.length < ipOffset + ipHeaderLength) {
            throw new IllegalArgumentException("Incomplete IPv4 options/header.");
        }

        int totalLength = readUnsignedShort(data, ipOffset + 2);

        if (totalLength < ipHeaderLength) {
            throw new IllegalArgumentException("Invalid IPv4 total length.");
        }

        if (totalLength > data.length - ipOffset) {
            throw new IllegalArgumentException("Truncated IPv4 packet.");
        }

        int ipEnd = ipOffset + totalLength;

        int ttl = data[ipOffset + 8] & 0xFF;
        int ipProtocol = data[ipOffset + 9] & 0xFF;

        String sourceIp = readIpAddress(data, ipOffset + 12);
        String destinationIp = readIpAddress(data, ipOffset + 16);

        // Step 5: Check IPv4 fragmentation.
        int fragmentField = readUnsignedShort(data, ipOffset + 6);

        int fragmentOffset = fragmentField & 0x1FFF;
        boolean moreFragments = (fragmentField & 0x2000) != 0;

        int transportOffset = ipOffset + ipHeaderLength;
        int transportHeaderLength = 0;

        int sourcePort = -1;
        int destinationPort = -1;
        int tcpFlags = 0;

        String transportProtocol;
        int payloadOffset = transportOffset;
        int payloadEnd = ipEnd;

        // Non-initial fragments do not contain the start
        // of the TCP/UDP header.
        if (fragmentOffset != 0) {

            transportProtocol = "FRAGMENT";

        } else if (ipProtocol == IP_PROTOCOL_TCP) {

            transportProtocol = "TCP";

            // TCP minimum header length is 20 bytes.
            if (ipEnd < transportOffset + 20) {
                throw new IllegalArgumentException("Incomplete TCP header.");
            }

            sourcePort = readUnsignedShort(data, transportOffset);
            destinationPort = readUnsignedShort(data, transportOffset + 2);

            transportHeaderLength =
                    ((data[transportOffset + 12] & 0xF0) >> 4) * 4;

            if (transportHeaderLength < 20) {
                throw new IllegalArgumentException("Invalid TCP header length.");
            }

            if (ipEnd < transportOffset + transportHeaderLength) {
                throw new IllegalArgumentException("Incomplete TCP options/header.");
            }

            // Include the TCP NS flag as bit 8.
            tcpFlags =
                    ((data[transportOffset + 12] & 0x01) << 8)
                            | (data[transportOffset + 13] & 0xFF);

            payloadOffset = transportOffset + transportHeaderLength;

        } else if (ipProtocol == IP_PROTOCOL_UDP) {

            transportProtocol = "UDP";

            // UDP header is always 8 bytes.
            if (ipEnd < transportOffset + 8) {
                throw new IllegalArgumentException("Incomplete UDP header.");
            }

            sourcePort = readUnsignedShort(data, transportOffset);
            destinationPort = readUnsignedShort(data, transportOffset + 2);

            int udpLength = readUnsignedShort(data, transportOffset + 4);

            if (udpLength < 8) {
                throw new IllegalArgumentException("Invalid UDP length.");
            }

            int availableUdpLength = ipEnd - transportOffset;

            if (!moreFragments && udpLength > availableUdpLength) {
                throw new IllegalArgumentException("UDP length exceeds IPv4 payload.");
            }

            transportHeaderLength = 8;

            payloadOffset = transportOffset + transportHeaderLength;

            // Do not include bytes outside the UDP datagram.
            // For fragmented UDP, the first fragment may not
            // contain the entire UDP datagram.
            payloadEnd = Math.min(
                    ipEnd,
                    transportOffset + udpLength
            );

        } else {

            transportProtocol = "OTHER";
        }

        // Step 6: Extract application payload.
        byte[] payload = copyBytes(
                data,
                payloadOffset,
                payloadEnd
        );

        // Step 7: Return structured packet information.
        return new ParsedPacket(
                sourceMac,
                destinationMac,
                etherType,
                sourceIp,
                destinationIp,
                ttl,
                ipProtocol,
                transportProtocol,
                sourcePort,
                destinationPort,
                tcpFlags,
                ethernetHeaderLength,
                ipHeaderLength,
                transportHeaderLength,
                payload
        );
    }

    private static boolean isVlan(int etherType) {
        return etherType == ETHERTYPE_VLAN
                || etherType == ETHERTYPE_QINQ
                || etherType == ETHERTYPE_VLAN_9100;
    }

    private static int readUnsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private static String readMacAddress(byte[] data, int offset) {

        return String.format(
                "%02X:%02X:%02X:%02X:%02X:%02X",
                data[offset] & 0xFF,
                data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF,
                data[offset + 3] & 0xFF,
                data[offset + 4] & 0xFF,
                data[offset + 5] & 0xFF
        );
    }

    private static String readIpAddress(byte[] data, int offset) {

        return (data[offset] & 0xFF) + "."
                + (data[offset + 1] & 0xFF) + "."
                + (data[offset + 2] & 0xFF) + "."
                + (data[offset + 3] & 0xFF);
    }

    private static byte[] copyBytes(
            byte[] data,
            int start,
            int end
    ) {
        if (start < 0 || end < start || end > data.length) {
            throw new IllegalArgumentException("Invalid packet payload boundaries.");
        }

        return java.util.Arrays.copyOfRange(data, start, end);
    }
}
