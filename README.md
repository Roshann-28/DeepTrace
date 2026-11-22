# DeepTrace

**DeepTrace is a Java-based, multithreaded packet analyzer for offline PCAP traffic.** It parses network packets, extracts visible protocol metadata, tracks connections, classifies supported application traffic, applies filtering rules, and writes allowed packets to a new PCAP file.

## Features

- **PCAP processing:** Read packet captures and write filtered capture files.
- **Packet parsing:** Parse Ethernet, IPv4, TCP, and UDP packet information.
- **Connection tracking:** Track flows using network connection identifiers (five-tuples).
- **Application detection:** Use available protocol and metadata signals to identify supported applications.
- **Protocol metadata extraction:** Extract supported DNS queries, HTTP Host information, and TLS SNI.
- **QUIC inspection:** Process supported QUIC Initial packets.
- **Rule-based filtering:** Filter packets based on IP addresses, domains, or detected applications.
- **Multithreaded processing:** Distribute packet processing across worker threads using bounded queues and a five-tuple hash-based load balancer.
- **Filtered PCAP output:** Write allowed packets to an output capture file.
- **CLI:** Configure input/output files, worker count, queue capacity, and filtering rules from the command line.

## Processing pipeline

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
Load Balancer (FiveTuple-based routing)
    |
    +----> Worker queues / worker threads
    |          |
    |          v
    |      FastPath
    |          |
    |          +--> Connection tracking
    |          +--> Metadata extraction / application detection
    |          +--> Rule evaluation
    |          |
    |          v
    |      Processing result
    |
    v
Output processing
    |
    +---- Allowed packets ----> PCAP Writer ----> Output PCAP
    |
    +---- Blocked packets ---> Excluded from output
```

DeepTrace analyzes saved packet captures. Filtering a packet means excluding it from the generated output PCAP; it does **not** block traffic on a live network interface.

## Technology stack

- **Java 25** — application implementation
- **Maven** — build and dependency management
- **JUnit 5** — automated tests
- **Java concurrency utilities** — worker threads and bounded blocking queues
- **PCAP binary file handling** — packet capture reading and writing

## Requirements

- Java JDK 25
- Apache Maven

## Build

From the project root:

```bash
mvn package
```

The packaged JAR is generated in the `target/` directory:

```text
target/deeptrace-1.0.0.jar
```

## Usage

Show the command-line help:

```bash
java -jar target/deeptrace-1.0.0.jar --help
```

Analyze a packet capture:

```bash
java -jar target/deeptrace-1.0.0.jar input.pcap output.pcap
```

Run with eight workers:

```bash
java -jar target/deeptrace-1.0.0.jar input.pcap output.pcap --workers 8
```

Set worker queue capacity:

```bash
java -jar target/deeptrace-1.0.0.jar input.pcap output.pcap --queue-capacity 1000
```

Filter packets matching an IP address:

```bash
java -jar target/deeptrace-1.0.0.jar input.pcap output.pcap --block-ip 192.168.1.10
```

Filter packets matching a domain:

```bash
java -jar target/deeptrace-1.0.0.jar input.pcap output.pcap --block-domain youtube.com
```

Filter packets matching a detected application:

```bash
java -jar target/deeptrace-1.0.0.jar input.pcap output.pcap --block-app YOUTUBE
```

Available CLI options:

| Option | Description |
|---|---|
| `--workers <number>` | Number of worker threads |
| `--queue-capacity <number>` | Capacity of each worker queue |
| `--block-ip <ip>` | Filter packets matching an IP address |
| `--block-domain <domain>` | Filter packets matching a domain |
| `--block-app <app>` | Filter packets matching a detected application |
| `--help`, `-h` | Display usage information |

## Tests

The current automated test suite contains **167 tests**. The latest verified run completed with no failures, errors, or skipped tests:

```text
Tests run: 167, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Run the tests with:

```bash
mvn test
```

## Verified sample run

DeepTrace was run against `test_dpi.pcap` with eight worker threads and no filtering rules:

| Metric | Result |
|---|---:|
| Packets read | 77 |
| Packets processed | 77 |
| Allowed packets | 77 |
| Blocked packets | 0 |
| Worker failures | 0 |
| Routing failures | 0 |
| Output failures | 0 |

With no filtering rules configured, all 77 packets were written to the output PCAP.

## Supported protocols and analysis scope

| Protocol / layer | Current scope |
|---|---|
| Ethernet | Frame parsing |
| IPv4 | Address and protocol parsing |
| TCP | Header and port parsing |
| UDP | Header and port parsing |
| DNS | Query metadata extraction where supported |
| HTTP | Host metadata extraction where supported |
| TLS | SNI extraction where visible and supported |
| QUIC | Supported Initial packet processing |

## Limitations

- Offline PCAP analysis only; live capture and live packet blocking are not implemented.
- HTTPS payloads are not decrypted.
- TLS SNI and domain extraction depend on metadata being present, visible, and supported by the parser.
- Full TCP stream reassembly is not implemented.
- IPv6 analysis is not implemented.
- QUIC inspection is limited and does not cover every QUIC version or packet/frame variation.
- Application detection uses available signatures and metadata; unknown traffic may remain unclassified.
- Filtering removes matching packets from the output capture; it does not enforce rules on a live network.

## License

DeepTrace is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
