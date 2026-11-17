# Packet Analyzer 

A Deep Packet Inspection (DPI) application that reads packet capture files, analyzes network traffic, identifies application protocols and domains, applies filtering rules, and writes permitted packets to a new PCAP file.

> **Project status:** This project is being developed phase by phase. This README describes the target Java architecture. Features will be marked as implemented as each phase is completed.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [What Is Deep Packet Inspection](#2-what-is-deep-packet-inspection)
3. [Core Features](#3-core-features)
4. [How Packet Analysis Works](#4-how-packet-analysis-works)
5. [Java Technology Stack](#5-java-technology-stack)
6. [Planned Project Structure](#6-planned-project-structure)
7. [Development Phases](#7-development-phases)
8. [PCAP File Format](#8-pcap-file-format)
9. [Supported Protocols](#9-supported-protocols)
10. [Build and Run](#10-build-and-run)
11. [Sample Usage](#11-sample-usage)
12. [Testing](#12-testing)
13. [Limitations and Notes](#13-limitations-and-notes)

---

## 1. Project Overview

Packet Analyzer is a Java application for inspecting network traffic stored in PCAP (Packet Capture) files.

The application is designed to:

- Read packets from a PCAP file.
- Parse Ethernet, IPv4, TCP, and UDP headers.
- Identify network flows using a five-tuple.
- Inspect application payloads where the required information is available.
- Extract TLS Server Name Indication (SNI), HTTP Host, and DNS query information.
- Classify traffic into known application categories.
- Apply rules to block traffic based on IP address, port, application, or domain.
- Write permitted packets to an output PCAP file.
- Generate packet, flow, and application statistics.

The initial development target is offline PCAP analysis. Live network capture and packet injection are outside the initial scope.

### High-level workflow

```text
             Input PCAP
                 |
                 v
            PCAP Reader
                 |
                 v
           Packet Parser
                 |
                 v
          Flow Identification
                 |
                 v
        Deep Packet Inspection
                 |
                 v
       Application Classification
                 |
                 v
           Rule Evaluation
                 |
          +------+------+
          |             |
          v             v
       Allowed        Blocked
          |             |
          v             v
     Output PCAP    Omitted from output
          |
          v
     Analysis Report
```

---

## 2. What Is Deep Packet Inspection

**Deep Packet Inspection (DPI)** examines packet headers and, when available, application-layer data.

A traditional packet filter may make decisions using source IP, destination IP, protocol, and port. A DPI system can also inspect selected application-layer information to help identify the service or domain associated with a flow.

### Network layers used by this project

| Layer | Examples | Information used |
|---|---|---|
| Application | HTTP, TLS, DNS | Host names and protocol details |
| Transport | TCP, UDP | Ports, flags, payload boundaries |
| Network | IPv4 | Source and destination IP addresses |
| Data Link | Ethernet | MAC addresses and frame type |

### Important note about HTTPS

HTTPS application data is encrypted. This project does not decrypt HTTPS traffic. It can inspect metadata that may be visible in a TLS handshake, such as SNI, when that information is present and accessible in the captured packets.

Encrypted Client Hello (ECH), fragmented handshakes, incomplete captures, and other protocol conditions can prevent a domain from being visible. SNI-based identification is therefore not guaranteed for every HTTPS connection.

---

## 3. Core Features

The Java implementation is planned to include:

| Feature | Description |
|---|---|
| PCAP reading | Read the PCAP global header and packet records |
| Packet parsing | Parse Ethernet, IPv4, TCP, and UDP headers |
| Flow tracking | Group packets using a five-tuple |
| TLS inspection | Extract SNI from supported TLS ClientHello messages |
| HTTP inspection | Extract the Host header from supported HTTP messages |
| DNS inspection | Read DNS query names |
| Application classification | Map recognized domains and protocol information to application categories |
| Rule management | Maintain IP, port, domain, and application blocking rules |
| Packet filtering | Write allowed packets to an output PCAP |
| Statistics | Report packet counts, flow counts, classifications, and dropped packets |
| Multithreading | Process independent flows concurrently in a later development phase |

These are intended capabilities, not a claim that every feature is already implemented.

---

## 4. How Packet Analysis Works

### Step 1: Read the PCAP file

The PCAP Reader opens the input file and reads its global header. It then reads packet records one at a time. Each record contains a timestamp, captured length, original packet length, and packet bytes.

### Step 2: Parse the packet

The Packet Parser examines packet bytes and identifies supported protocol headers. For supported Ethernet/IPv4 traffic, it extracts:

- Source and destination MAC addresses.
- Source and destination IPv4 addresses.
- Transport protocol.
- Source and destination ports for TCP or UDP.
- Payload offset and payload length.
- TCP flags, when applicable.

Malformed packets and unsupported protocols must be handled safely.

### Step 3: Identify the flow

A flow is identified using five values:

| Field | Example |
|---|---|
| Source IP | `192.168.1.100` |
| Destination IP | `172.217.14.206` |
| Source port | `54321` |
| Destination port | `443` |
| Protocol | TCP (`6`) |

Packets with the same directional five-tuple belong to the same flow. Reverse-direction handling can be added as a separate flow-tracking policy.

### Step 4: Inspect application data

The inspection stage examines supported payloads:

- TLS ClientHello messages may contain an SNI hostname.
- HTTP requests may contain a Host header.
- DNS queries contain requested domain names.

### Step 5: Classify the application

Recognized domains or protocol details can be mapped to application categories.

| Example domain | Example category |
|---|---|
| `youtube.com` | YouTube |
| `facebook.com` | Facebook |
| `google.com` | Google |
| `github.com` | GitHub |

Classification is signature-based and depends on information visible in the capture. An unknown or unavailable signature should remain `UNKNOWN` rather than being guessed.

### Step 6: Evaluate filtering rules

The Rule Manager evaluates configured rules. Planned rule categories include source IP address, destination port, application category, and domain name.

A packet matching a blocking rule is excluded from the output PCAP. Otherwise, its packet record and packet bytes are written to the output file.

### Step 7: Generate statistics

At the end of processing, the application reports total packets read, packets forwarded, packets dropped, flows observed, application classification counts, and detected domain names.

---

## 5. Java Technology Stack

| Technology | Purpose |
|---|---|
| Java 25 (LTS) | Main programming language and runtime |
| Maven | Project build and dependency management |
| `java.io` / `java.nio` | Binary PCAP file handling |
| `ByteBuffer` | Reading multi-byte network fields |
| Java collections | Flow tracking and rule storage |
| `ExecutorService` | Worker-thread management |
| `BlockingQueue` | Producer-consumer packet processing |
| JUnit 5 | Unit testing |

The first development phases will use the Java standard library wherever practical. Additional dependencies will be introduced only when they provide a clear benefit.

---

## 6. Planned Project Structure

The Java project will use the standard Maven directory layout.

```text
packet-analyzer-java/
├── pom.xml
├── README.md
├── test_dpi.pcap
├── output.pcap
└── src/
    ├── main/
    │   └── java/com/packetanalyzer/
    │       ├── Main.java
    │       ├── reader/
    │       │   ├── PcapReader.java
    │       │   ├── PcapWriter.java
    │       │   ├── PcapGlobalHeader.java
    │       │   └── PcapPacketHeader.java
    │       ├── parser/
    │       │   └── PacketParser.java
    │       ├── model/
    │       │   ├── RawPacket.java
    │       │   ├── ParsedPacket.java
    │       │   ├── FiveTuple.java
    │       │   └── AppType.java
    │       ├── extractor/
    │       │   ├── SNIExtractor.java
    │       │   ├── HTTPHostExtractor.java
    │       │   └── DNSExtractor.java
    │       ├── dpi/
    │       │   ├── DPIEngine.java
    │       │   ├── FastPathProcessor.java
    │       │   └── ConnectionTracker.java
    │       ├── balancer/
    │       │   └── LoadBalancer.java
    │       ├── rules/
    │       │   └── RuleManager.java
    │       └── utils/
    │           └── ThreadSafeQueue.java
    └── test/java/com/packetanalyzer/
```

The structure may be adjusted as implementation details become clear. Classes will be added when their responsibilities are needed.

---

## 7. Development Phases

Each phase will be implemented and tested before moving to the next one.

| Phase | Module | Main outcome |
|---|---|---|
| 1 | Project setup and PCAP Reader | Open a PCAP file and read packet records |
| 2 | Packet Parser | Parse Ethernet, IPv4, TCP, and UDP headers |
| 3 | Models and Five-Tuple | Represent packets, protocols, and network flows |
| 4 | Protocol Extractors | Extract supported TLS SNI, HTTP Host, and DNS query data |
| 5 | Connection Tracker and Rule Manager | Track flows and evaluate filtering rules |
| 6 | Fast Path Processor | Process and classify packets using worker threads |
| 7 | Load Balancer and DPI Engine | Coordinate packet distribution and processing |
| 8 | Main Application and Testing | Integrate modules, write output PCAPs, and generate reports |

---

## 8. PCAP File Format

The initial reader and writer target the classic PCAP file format.

```text
+-------------------------------+
| Global Header (24 bytes)      |
+-------------------------------+
| Packet Header (16 bytes)      |
| Packet Data (variable size)   |
+-------------------------------+
| Packet Header (16 bytes)      |
| Packet Data (variable size)   |
+-------------------------------+
| More packet records...        |
+-------------------------------+
```

### Global header

The global header stores the magic number, major and minor format version, time-zone correction field, timestamp accuracy field, maximum captured packet length (snapshot length), and link-layer type.

The magic number determines the file's byte order and whether timestamps use microsecond or nanosecond precision.

### Packet record header

Each packet record stores timestamp seconds, timestamp fractional component, captured packet length, and original packet length. The captured packet length determines how many packet bytes follow the record header.

The reader must validate lengths and handle end-of-file without treating a normal end-of-file as a malformed packet.

---

## 9. Supported Protocols

The planned initial parsing scope is:

| Protocol | Planned handling |
|---|---|
| Ethernet | Read frame header and EtherType |
| IPv4 | Read addresses, protocol number, and header length |
| TCP | Read ports, header length, flags, and payload |
| UDP | Read ports, datagram length, and payload |
| TLS | Extract SNI from supported ClientHello messages |
| HTTP | Extract Host from supported plaintext HTTP requests |
| DNS | Extract query names from supported DNS messages |

IPv6, VLAN tags, IP fragmentation/reassembly, advanced QUIC inspection, and other link-layer formats are potential future extensions unless added to the implementation plan.

---

## 10. Build and Run

### Prerequisites

Install:

1. JDK 25 or later.
2. Apache Maven.
3. An IDE such as IntelliJ IDEA or Visual Studio Code (optional).

Verify the installations:

```bash
java -version
javac -version
mvn -version
```

### Build the project

From the project root directory:

```bash
mvn clean package
```

### Run the application

The exact command-line options will be finalized when the Java `Main` class is implemented. The intended basic form is:

```bash
java -jar target/packet-analyzer-java.jar <input.pcap> <output.pcap>
```

Example:

```bash
java -jar target/packet-analyzer-java.jar test_dpi.pcap output.pcap
```

---

## 11. Sample Usage

The planned command-line interface will support an input PCAP, an output PCAP, and optional filtering rules.

Example of the intended interface:

```bash
java -jar target/packet-analyzer-java.jar capture.pcap filtered.pcap \
  --block-ip 192.168.1.50 \
  --block-app YouTube \
  --block-domain youtube.com \
  --block-port 443
```

These options describe the intended interface. They will become available as the corresponding rule-management and command-line phases are implemented.

---

## 12. Testing

The project includes PCAP samples and a test-capture generator. Planned tests include:

- Reading a valid PCAP global header.
- Reading packet records with correct timestamps and lengths.
- Handling empty, truncated, or invalid PCAP files.
- Parsing Ethernet and IPv4 headers.
- Parsing TCP and UDP headers.
- Extracting supported TLS SNI values.
- Extracting HTTP Host values and DNS query names.
- Tracking packets belonging to the same flow.
- Applying and rejecting blocking rules correctly.
- Verifying that output PCAP records are valid.
- Checking consistent results when multithreaded processing is enabled.

Unit tests will be added alongside each development phase.

---

## 13. Limitations and Notes

- This project initially analyzes saved PCAP files; it is not a live packet-capture tool.
- The application does not decrypt HTTPS payloads.
- SNI and HTTP Host extraction depend on the relevant bytes being present in the capture.
- Encrypted Client Hello, fragmentation, truncated captures, and unsupported protocol variations can limit classification.
- Application identification is based on available signatures and should not be treated as guaranteed identification.
- Blocking in this project means omitting matching packets from the generated output PCAP. It does not automatically block traffic on a live network interface.
- This README describes the target Java design. Implementation status will be updated as modules are completed.

---

## License

Add the project's license and attribution information here before distributing the application.
