# Java Byte & JVM Memory Mastery

<img src = "jvm.png"></img>

A comprehensive repository README capturing byte-level manipulation in Java and JVM memory inspection—covering fundamentals, practical recipes, advanced APIs, profiling, heap/thread tooling, and third-party ecosystems. No external assumptions; everything documented here comes from the transcript.

---
## Table of Contents

- [Core Bitwise & Shifts](#core-bitwise--shifts)
- [Conversions & Encodings](#conversions--encodings)
- [Buffers & I/O](#buffers--io)
- [Advanced Memory APIs](#advanced-memory-apis)
- [High-Performance Byte Containers](#high-performance-byte-containers)
- [Serialization & Protocols](#serialization--protocols)
- [Parsing DSLs](#parsing-dsls)
- [Bitmaps & Sets](#bitmaps--sets)
- [Compression](#compression)
- [Cryptography](#cryptography)
- [Native Interop](#native-interop)
- [Heap & Object Sizing](#heap--object-sizing)
- [Stack Inspection](#stack-inspection)
- [In-Process Monitoring APIs](#in-process-monitoring-apis)
- [JDK CLI Tools](#jdk-cli-tools)
- [Profilers (Free)](#profilers-free)
- [Profilers (Commercial)](#profilers-commercial)
- [Container Profiling](#container-profiling)
- [Low-Overhead Profilers](#low-overhead-profilers)
- [Heap/GC Analyzers](#heapgc-analyzers)
- [Agents & Bytecode Tools](#agents--bytecode-tools)
- [GC & Performance Testing](#gc--performance-testing)
- [Monitoring & Dashboards](#monitoring--dashboards)
- [Alternative JVMs & Vendor Tools](#alternative-jvms--vendor-tools)
- [IDE Profilers](#ide-profilers)
---

# Java Byte & JVM Memory — Tools, APIs, and Libraries

| Category | Item | Description |
|----------|------|-------------|
| **Core Bitwise & Shifts** | `&`, `|`, `^`, `~` | Core bitwise operators: AND, OR, XOR, NOT |
|  | `<<`, `>>`, `>>>` | Left, arithmetic right, logical right shifts |
|  | `Integer.rotateLeft/rotateRight` | Bit rotations (useful in crypto and mixing) |
|  | `Integer.bitCount` | Population count (number of 1-bits) |
|  | `Integer.numberOfLeadingZeros` | Count leading zero bits |
|  | `Integer.numberOfTrailingZeros` | Count trailing zero bits |
| **Conversions & Encodings** | `HexFormat` | Hex encode/decode utility (Java 17+) |
|  | `Base64` | Standard Base64 encode/decode |
|  | `MessageDigest` | Cryptographic hashes (e.g., SHA-256) |
|  | `CRC32` | Fast checksum implementation |
|  | `StandardCharsets` | Correct charset constants for byte ↔ text |
| **Buffers & I/O** | `ByteBuffer` | Heap/direct buffers; endian-aware control |
|  | `ByteBuffer.allocateDirect` | Allocate direct (off-heap) buffer |
|  | `MappedByteBuffer` | Memory-mapped files; zero-copy access |
|  | `slice()`, `asIntBuffer()` | Create views over buffers without copying |
|  | `FileChannel` | Random access + memory-mapping |
|  | `DataInputStream`, `DataOutputStream` | Simple binary protocols (big-endian, UTF) |
| **Advanced Memory APIs** | `VarHandle` | Low-level, safe ordered/atomic access |
|  | **Project Panama (Foreign Memory API)** | Off-heap structured memory with explicit `MemoryLayout` (JDK 22+) |
|  | `sun.misc.Unsafe` | Raw memory operations; non-portable, last resort |
| **High-Performance Byte Containers** | Netty `ByteBuf` | Reference-counted, pooled, zero-copy slices |
|  | Agrona `DirectBuffer` | Flyweight views over heap/off-heap memory |
|  | Chronicle Bytes | Off-heap bytes, memory-mapped files, logs |
| **Serialization & Protocols** | Protocol Buffers | Schema-based, compact binary format |
|  | Avro | Schema-based serialization |
|  | SBE (Simple Binary Encoding) | Low-latency fixed-schema serialization |
|  | FlatBuffers | Zero-copy serialization (no parsing step) |
|  | Cap’n Proto | Zero-copy, cross-language serialization |
|  | Kryo | Fast general-purpose object serialization |
|  | Protostuff | Alternative to Kryo for fast serialization |
|  | MessagePack | Compact binary JSON-like format |
|  | CBOR | Concise Binary Object Representation |
|  | BSON | Binary JSON (MongoDB format) |
| **Parsing DSLs** | Kaitai Struct | DSL + codegen for binary format parsing |
|  | JBBP | Java Bit-Byte Parser (parse bitfields, packed data) |
| **Bitmaps & Sets** | RoaringBitmap | Compressed bitmaps for large integer sets |
|  | JavaEWAH | Word-aligned compressed bitmaps |
| **Compression** | LZ4 | High-speed compression |
|  | Zstd | Fast modern compression with high ratios |
|  | Snappy | Google’s fast compression algorithm |
|  | Brotli | Web-optimized compression |
|  | GZIP/Deflate | Standard compression algorithms |
| **Cryptography** | BouncyCastle | Comprehensive crypto library for Java |
| **Native Interop** | JNI | Manual Java ↔ native binding |
|  | JNA / JNR-FFI | Easier Java ↔ native interop |
| **Heap & Object Sizing** | `Runtime.getRuntime()` | Get JVM heap memory sizes |
|  | `Instrumentation#getObjectSize` | Get shallow object size |
|  | JOL (Java Object Layout) | Inspect per-field layout, headers, padding |
|  | Jamm | Agent-based retained size measurement |
|  | Carrotsearch SizeOf | Retained size estimator (used in Lucene) |
|  | Lucene’s `RamUsageEstimator` | Utility for object memory usage |
| **Stack Inspection** | `Thread.getAllStackTraces()` | Inspect all thread stacks |
|  | `Thread.dumpStack()` | Dump current thread stack |
|  | `StackWalker` | Fast current-thread stack inspection |
|  | `ThreadMXBean` | Thread monitoring, CPU time, deadlocks |
| **In-Process Monitoring APIs** | `MemoryMXBean` | Overall memory pools & GC |
|  | `MemoryPoolMXBean` | Memory pool usage (eden, survivor, old) |
|  | `GarbageCollectorMXBean` | GC stats |
|  | `BufferPoolMXBean` | Direct buffer usage |
| **JDK CLI Tools** | `jcmd` | Swiss-army knife: GC, heap, threads, JFR |
|  | `jmap` | Heap summaries, histograms, dumps |
|  | `jstack` | Thread stack dumps |
|  | `jstat` | GC/class loader stats over time |
|  | `jinfo` | JVM flags at runtime |
|  | `jhsdb` | Serviceability Agent (jmap/jstack replacements) |
|  | `jconsole` | GUI monitor bundled with JDK |
|  | VisualVM | GUI profiler & heap/thread analyzer |
|  | `jfr` | Java Flight Recorder tool |
| **Profilers (Free)** | Java Flight Recorder (JFR) | Low-overhead profiling & telemetry |
|  | Java Mission Control (JMC) | GUI to analyze JFR recordings |
|  | VisualVM | Heap, CPU, thread profiling |
|  | Eclipse MAT | Heap dump analysis (dominator trees, leaks) |
|  | GCViewer | GC log analysis |
| **Profilers (Commercial)** | YourKit | Full CPU/memory profiler |
|  | JProfiler | Comprehensive commercial profiler |
|  | AppDynamics / Dynatrace / New Relic / Datadog APM | Production-grade telemetry |
| **Container Profiling** | Cryostat (ContainerJFR) | Manage JFR on Kubernetes/containers |
| **Low-Overhead Profilers** | async-profiler | Native sampler: CPU, allocs, locks, flame graphs |
|  | Honest Profiler | Async sampling profiler |
|  | Linux `perf` + perf-map-agent | System-level sampling |
|  | FlameGraph | Visualization of profiler stacks |
| **Heap/GC Analyzers** | Eclipse MAT | Heap dump analysis |
|  | HeapHero, GCeasy, yCrash, fastThread | Online GC/heap analysis |
|  | HPJMeter / IBM PMAT | Legacy enterprise GC analyzers |
| **Agents & Bytecode Tools** | `java.lang.instrument` | Agent instrumentation API |
|  | Byte Buddy | High-level runtime instrumentation |
|  | ASM | Low-level bytecode manipulation |
|  | BTrace | Dynamic tracing with scripts |
|  | Byteman | Rule-based bytecode injection |
|  | JFR Event Streaming | Emit/consume live custom events |
|  | HPROF | Legacy profiler (deprecated) |
| **GC & Performance Testing** | JMH (Java Microbenchmark Harness) | Benchmarking with GC profiling |
|  | JUnit + JFR | Scenario tests with allocation budgets |
|  | Caliper | Legacy benchmarking framework |
| **Monitoring & Dashboards** | JMX (remote) | Connect GUIs like JMC/VisualVM |
|  | Jolokia | JMX over HTTP/JSON |
|  | Micrometer + Prometheus + Grafana | Metrics dashboards |
| **Alternative JVMs & Vendor Tools** | OpenJ9 | IBM’s JVM (tools: jdmpview, MAT) |
|  | Azul Zing/Zulu | C4 GC diagnostics, JMC integrations |
|  | SAP Machine | HotSpot-compatible distribution |
| **IDE Profilers** | IntelliJ Profiler | JFR/async-profiler integration |
|  | NetBeans Profiler | VisualVM-based profiler |
|  | Eclipse + MAT | Dump analysis integration |

---

# General Number System Representations

| System        | Base | Digits Used                     | Example for 42 | Notes                                  |
|---------------|------|---------------------------------|----------------|----------------------------------------|
| Binary        | 2    | 0, 1                           | `101010`       | Machine-level, bitwise ops, flags      |
| Octal         | 8    | 0–7                            | `52`           | Old UNIX file perms, compact grouping  |
| Decimal       | 10   | 0–9                            | `42`           | Human default numbering                |
| Hexadecimal   | 16   | 0–9, A–F                       | `2A`           | Compact binary representation, colors  |
| Base32        | 32   | A–Z, 2–7                       | `16` → `G`     | Encoding, checksums, identifiers       |
| Base36        | 36   | 0–9, A–Z                       | `42` → `16`    | Short IDs, URL shorteners              |
| Base58        | 58   | 1–9, A–H, J–N, P–Z, a–k, m–z   | `42` → `h`     | Bitcoin, avoids look-alike chars       |
| Base64        | 64   | A–Z, a–z, 0–9, +, /            | `42` → `Kg==`  | Encoding binary as text (e.g., email)  |
| Roman Numeral | —    | I, V, X, L, C, D, M            | `XLII`         | Historical numbering system            |

# Numeric Systems in Java

| System        | Prefix / Syntax | Example Literal        | Base | Notes                                        |
|---------------|-----------------|------------------------|------|----------------------------------------------|
| Decimal       | (none)          | `42`                   | 10   | Default representation of integers           |
| Binary        | `0b` or `0B`    | `0b101010` (42)        | 2    | Added in Java 7                              |
| Octal         | Leading `0`     | `052` (42)             | 8    | Leading zero means octal (⚠ deprecated style)|
| Hexadecimal   | `0x` or `0X`    | `0x2A` (42)            | 16   | Common for bit manipulation                  |
| Floating-point| Decimal or sci. | `3.14`, `6.02e23`      | 10   | Supports scientific notation (`e`/`E`)       |
| Underscores   | Between digits  | `1_000_000`            | —    | Improves readability (Java 7+)               |

# General Boolean Algebra Truth Table

| A | B | NOT A | A AND B | A OR B | A XOR B | A NAND B | A NOR B | A XNOR B |
|---|---|-------|---------|--------|---------|----------|---------|----------|
| 0 | 0 |   1   |    0    |   0    |    0    |    1     |    1    |    1     |
| 0 | 1 |   1   |    0    |   1    |    1    |    1     |    0    |    0     |
| 1 | 0 |   0   |    0    |   1    |    1    |    1     |    0    |    0     |
| 1 | 1 |   0   |    1    |   1    |    0    |    0     |    0    |    1     |

# Logical Operators in Java

| Operator | Name             | Type        | Example        | Notes                                                      |
|----------|------------------|-------------|----------------|------------------------------------------------------------|
| `&&`     | Logical AND      | Short-circuit | `a && b`     | Evaluates `b` only if `a` is true                         |
| `&`      | Bitwise AND      | Non-short    | `a & b`       | Works on booleans and integers (bitwise)                  |
| `||`     | Logical OR       | Short-circuit | `a || b`     | Evaluates `b` only if `a` is false                        |
| `|`      | Bitwise OR       | Non-short    | `a | b`       | Works on booleans and integers (bitwise)                  |
| `^`      | XOR (exclusive)  | Bitwise/logical | `a ^ b`    | True if operands differ; bitwise on numbers               |
| `!`      | NOT              | Unary        | `!a`          | Negates boolean                                            |
| `==`     | Equality         | Comparison   | `a == b`      | Compares boolean values or numbers                        |
| `!=`     | Inequality       | Comparison   | `a != b`      | Opposite of equality                                      |
| `~`      | Bitwise NOT      | Unary        | `~x`          | Inverts all bits of an integer                            |


# Java Boolean Truth Tables

## AND (`&&` / `&`)
| A     | B     | A && B |
|-------|-------|--------|
| true  | true  | true   |
| true  | false | false  |
| false | true  | false  |
| false | false | false  |


## OR (`||` / `|`)
| A     | B     | A || B |
|-------|-------|--------|
| true  | true  | true   |
| true  | false | true   |
| false | true  | true   |
| false | false | false  |


## XOR (`^`)
| A     | B     | A ^ B  |
|-------|-------|--------|
| true  | true  | false  |
| true  | false | true   |
| false | true  | true   |
| false | false | false  |

## NOT (`!`)
| A     | !A    |
|-------|-------|
| true  | false |
| false | true  |

## Bytes in Java

| Property       | Details                                   |
|----------------|-------------------------------------------|
| Type           | `byte` (8-bit signed integer)             |
| Range          | `-128` to `127`                           |
| Representation | Two’s complement                          |
| Examples       | `01001100₂ = 76₁₀`, `11111111₂ = -1₁₀`   |

# Java Byte & JVM Memory — Tools, APIs, and Libraries

# Java Numeric Data Types

| Type   | Size (bits) | Wrapper Class | Min Value                       | Max Value                       | Default Value | Notes                                  |
|--------|-------------|---------------|---------------------------------|---------------------------------|---------------|----------------------------------------|
| byte   | 8           | Byte          | -128                            | 127                             | 0             | Signed 2’s complement                   |
| short  | 16          | Short         | -32,768                         | 32,767                          | 0             | Signed 2’s complement                   |
| int    | 32          | Integer       | -2,147,483,648 (-2^31)          | 2,147,483,647 (2^31 - 1)        | 0             | Most common integer type                |
| long   | 64          | Long          | -9,223,372,036,854,775,808      | 9,223,372,036,854,775,807       | 0L            | Use `L` suffix for literals             |
| float  | 32          | Float         | ~1.4E-45                        | ~3.4E38                         | 0.0f          | IEEE 754 single precision, 6–7 digits   |
| double | 64          | Double        | ~4.9E-324                       | ~1.8E308                        | 0.0d          | IEEE 754 double precision, 15–16 digits |
| char   | 16          | Character     | 0                               | 65,535 (unsigned)               | '\u0000'      | UTF-16 code unit, not negative          |


## Core Bitwise & Shifts

| Item | Description |
|------|-------------|
| `&`, `|`, `^`, `~` | Core bitwise operators: AND, OR, XOR, NOT |
| `<<`, `>>`, `>>>` | Left, arithmetic right, logical right shifts |
| `Integer.rotateLeft/rotateRight` | Bit rotations (useful in crypto and mixing) |
| `Integer.bitCount` | Population count (number of 1-bits) |
| `Integer.numberOfLeadingZeros` | Count leading zero bits |
| `Integer.numberOfTrailingZeros` | Count trailing zero bits |

---

## Conversions & Encodings

| Item | Description |
|------|-------------|
| `HexFormat` | Hex encode/decode utility (Java 17+) |
| `Base64` | Standard Base64 encode/decode |
| `MessageDigest` | Cryptographic hashes (e.g., SHA-256) |
| `CRC32` | Fast checksum implementation |
| `StandardCharsets` | Correct charset constants for byte ↔ text |

---

## Buffers & I/O

| Item | Description |
|------|-------------|
| `ByteBuffer` | Heap/direct buffers; endian-aware control |
| `ByteBuffer.allocateDirect` | Allocate direct (off-heap) buffer |
| `MappedByteBuffer` | Memory-mapped files; zero-copy access |
| `slice()`, `asIntBuffer()` | Create views over buffers without copying |
| `FileChannel` | Random access + memory-mapping |
| `DataInputStream`, `DataOutputStream` | Simple binary protocols (big-endian, UTF) |

---

## Advanced Memory APIs

| Item | Description |
|------|-------------|
| `VarHandle` | Low-level, safe ordered/atomic access |
| **Project Panama (Foreign Memory API)** | Off-heap structured memory with explicit `MemoryLayout` (JDK 22+) |
| `sun.misc.Unsafe` | Raw memory operations; non-portable, last resort |

---

## High-Performance Byte Containers

| Library | Description |
|---------|-------------|
| Netty `ByteBuf` | Reference-counted, pooled, zero-copy slices |
| Agrona `DirectBuffer` | Flyweight views over heap/off-heap memory |
| Chronicle Bytes | Off-heap bytes, memory-mapped files, logs |

---

## Serialization & Protocols

| Library | Description |
|---------|-------------|
| Protocol Buffers | Schema-based, compact binary format |
| Avro | Schema-based serialization |
| SBE (Simple Binary Encoding) | Low-latency fixed-schema serialization |
| FlatBuffers | Zero-copy serialization (no parsing step) |
| Cap’n Proto | Zero-copy, cross-language serialization |
| Kryo | Fast general-purpose object serialization |
| Protostuff | Alternative to Kryo for fast serialization |
| MessagePack | Compact binary JSON-like format |
| CBOR | Concise Binary Object Representation |
| BSON | Binary JSON (MongoDB format) |

---

## Parsing DSLs

| Library | Description |
|---------|-------------|
| Kaitai Struct | DSL + codegen for binary format parsing |
| JBBP | Java Bit-Byte Parser (parse bitfields, packed data) |

---

## Bitmaps & Sets

| Library | Description |
|---------|-------------|
| RoaringBitmap | Compressed bitmaps for large integer sets |
| JavaEWAH | Word-aligned compressed bitmaps |

---

## Compression

| Library | Description |
|---------|-------------|
| LZ4 | High-speed compression |
| Zstd | Fast modern compression with high ratios |
| Snappy | Google’s fast compression algorithm |
| Brotli | Web-optimized compression |
| GZIP/Deflate | Standard compression algorithms |

---

## Cryptography

| Library | Description |
|---------|-------------|
| BouncyCastle | Comprehensive crypto library for Java |

---

## Native Interop

| Tool | Description |
|------|-------------|
| JNI | Manual Java ↔ native binding |
| JNA / JNR-FFI | Easier Java ↔ native interop |

---

## Heap & Object Sizing

| Tool/Library | Description |
|--------------|-------------|
| `Runtime.getRuntime()` | Get JVM heap memory sizes |
| `Instrumentation#getObjectSize` | Get shallow object size |
| JOL (Java Object Layout) | Inspect per-field layout, headers, padding |
| Jamm | Agent-based retained size measurement |
| Carrotsearch SizeOf | Retained size estimator (used in Lucene) |
| Lucene’s `RamUsageEstimator` | Utility for object memory usage |

---

## Stack Inspection

| Tool/API | Description |
|----------|-------------|
| `Thread.getAllStackTraces()` | Inspect all thread stacks |
| `Thread.dumpStack()` | Dump current thread stack |
| `StackWalker` | Fast current-thread stack inspection |
| `ThreadMXBean` | Thread monitoring, CPU time, deadlocks |

---

## In-Process Monitoring APIs

| API | Description |
|-----|-------------|
| `MemoryMXBean` | Overall memory pools & GC |
| `MemoryPoolMXBean` | Memory pool usage (eden, survivor, old) |
| `GarbageCollectorMXBean` | GC stats |
| `BufferPoolMXBean` | Direct buffer usage |
| `ThreadMXBean` | Thread stats & deadlock detection |

---

## JDK CLI Tools

| Tool | Purpose |
|------|---------|
| `jcmd` | Swiss-army knife: GC, heap, threads, JFR |
| `jmap` | Heap summaries, histograms, dumps |
| `jstack` | Thread stack dumps |
| `jstat` | GC/class loader stats over time |
| `jinfo` | JVM flags at runtime |
| `jhsdb` | Serviceability Agent (jmap/jstack replacements) |
| `jconsole` | GUI monitor bundled with JDK |
| VisualVM | GUI profiler & heap/thread analyzer |
| `jfr` | Java Flight Recorder tool |

---

## Profilers (Free)

| Tool | Description |
|------|-------------|
| Java Flight Recorder (JFR) | Low-overhead profiling & telemetry |
| Java Mission Control (JMC) | GUI to analyze JFR recordings |
| VisualVM | Heap, CPU, thread profiling |
| Eclipse MAT | Heap dump analysis (dominator trees, leaks) |
| GCViewer | GC log analysis |

---

## Profilers (Commercial)

| Tool | Description |
|------|-------------|
| YourKit | Full CPU/memory profiler |
| JProfiler | Comprehensive commercial profiler |
| AppDynamics / Dynatrace / New Relic / Datadog APM | Production-grade telemetry |

---

## Container Profiling

| Tool | Description |
|------|-------------|
| Cryostat (ContainerJFR) | Manage JFR on Kubernetes/containers |

---

## Low-Overhead Profilers

| Tool | Description |
|------|-------------|
| async-profiler | Native sampler: CPU, allocs, locks, flame graphs |
| Honest Profiler | Async sampling profiler |
| Linux `perf` + perf-map-agent | System-level sampling |
| FlameGraph | Visualization of profiler stacks |

---

## Heap/GC Analyzers

| Tool | Description |
|------|-------------|
| Eclipse MAT | Heap dump analysis |
| HeapHero | Online GC/heap analysis |
| GCeasy | Online GC/heap analysis |
| yCrash | Online GC/heap analysis |
| fastThread | Online GC/heap analysis |
| HPJMeter / IBM PMAT | Legacy enterprise GC analyzers |

---

## Agents & Bytecode Tools

| Tool | Description |
|------|-------------|
| `java.lang.instrument` | Agent instrumentation API |
| Byte Buddy | High-level runtime instrumentation |
| ASM | Low-level bytecode manipulation |
| BTrace | Dynamic tracing with scripts |
| Byteman | Rule-based bytecode injection |
| JFR Event Streaming | Emit/consume live custom events |
| HPROF | Legacy profiler (deprecated) |

---

## GC & Performance Testing

| Tool | Description |
|------|-------------|
| JMH (Java Microbenchmark Harness) | Benchmarking with GC profiling |
| JUnit + JFR | Scenario tests with allocation budgets |
| Caliper | Legacy benchmarking framework |

---

## Monitoring & Dashboards

| Tool | Description |
|------|-------------|
| JMX (remote) | Connect GUIs like JMC/VisualVM |
| Jolokia | JMX over HTTP/JSON |
| Micrometer + Prometheus + Grafana | Metrics dashboards |

---

## Alternative JVMs & Vendor Tools

| JVM/Tool | Description |
|----------|-------------|
| OpenJ9 | IBM’s JVM (tools: jdmpview, MAT) |
| Azul Zing/Zulu | C4 GC diagnostics, JMC integrations |
| SAP Machine | HotSpot-compatible distribution |

---

## IDE Profilers

| Tool | Description |
|------|-------------|
| IntelliJ Profiler | JFR/async-profiler integration |
| NetBeans Profiler | VisualVM-based profiler |
| Eclipse + MAT | Dump analysis integration |

---
