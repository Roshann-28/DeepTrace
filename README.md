# DeepTrace – Java-Based Deep Packet Inspection System

DeepTrace is a Java-based network traffic analysis and Deep Packet Inspection (DPI) project. It is being implemented incrementally, beginning with classic PCAP file reading.

## Technology

- Java 17
- Maven
- Java I/O and NIO
- JUnit tests will be introduced as the project develops

## Current implementation status

### Phase 1 – PCAP Reader
- [x] Maven project structure
- [x] PCAP global header parsing
- [x] Little-endian and big-endian classic PCAP detection
- [x] Microsecond and nanosecond timestamp formats
- [x] Sequential packet-record reading
- [x] Basic malformed/truncated input checks
- [ ] Automated unit tests

Later phases will add packet parsing, flow tracking, protocol extraction, rule management, multithreaded processing, output PCAP writing, and reporting.

## Project structure

```text
DeepTrace/
├── pom.xml
├── README.md
└── src/main/java/com/deeptrace/
    ├── Main.java
    └── reader/
        ├── PcapReader.java
        ├── PcapGlobalHeader.java
        ├── PcapPacketHeader.java
        └── RawPacket.java
```

## Prerequisites

Install JDK 17 or later and Maven. Verify the installations:

```bash
java -version
javac -version
mvn -version
```

## Build

From the project root:

```bash
mvn clean package
```

## Run

```bash
java -jar target/deeptrace-1.0.0.jar test_dpi.pcap
```

The current Phase 1 application prints the PCAP metadata, displays information about the first five packet records, and reports the total number of records read.

## PCAP scope

The current reader supports classic PCAP files (not PCAPNG). It recognizes both byte orders and both microsecond and nanosecond timestamp variants. Packet contents are read as raw bytes; protocol parsing is part of Phase 2.

## License

No open-source license has been applied to this project. All rights are reserved by the project owner. The source code is publicly available for viewing, but reuse, modification, or redistribution requires prior permission.
