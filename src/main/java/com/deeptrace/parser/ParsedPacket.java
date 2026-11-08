package com.deeptrace.parser;

public record ParsedPacket (
        String sourceMac,
        String destinationMac,
        int etherType,

        String sourceIp,
        String destinationIp,

        int ttl,
        int ipProtocol,

        String transportProtocol,
        int sourcePort,
        int destinationPort,

        int tcpFlags,

        int ethernetHeaderLength,
        int ipHeaderLength,
        int transportHeaderLength,

        byte[] payload
    ){
    public ParsedPacket {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be Null");
        }

//        Prevent external modification of the original array
        payload = payload.clone();

    }

    @Override
    public byte[] payload(){
            return payload.clone();
    }

    public int payloadLength(){
        return payload.length;
    }

}
