# Java Byte & JVM Memory Mastery

A comprehensive repository README capturing byte-level manipulation in Java and JVM memory inspection—covering fundamentals, practical recipes, advanced APIs, profiling, heap/thread tooling, and third-party ecosystems. No external assumptions; everything documented here comes from the transcript.

---

## Contents

- [Bytes in Java](#bytes-in-java)
- [Bitwise Operations](#bitwise-operations)
- [Shift Operators](#shift-operators)
- [Practical Applications](#practical-applications)
- [Objects ↔ Bytes](#objects--bytes)
- [Professional Byte Manipulation](#professional-byte-manipulation)
  - [Standard Java Toolbox](#standard-java-toolbox)
  - [Advanced Low-Level APIs](#advanced-lowlevel-apis)
  - [Third-Party Power Tools](#thirdparty-power-tools)
  - [Practical Recipes](#practical-recipes)
  - [Decision Guide](#decision-guide)
  - [Pitfalls & Pro Tips](#pitfalls--pro-tips)
- [Heap & Stack Inspection](#heap--stack-inspection)
  - [From Inside Your Code](#from-inside-your-code)
  - [Built-in JDK Tools (CLI)](#builtin-jdk-tools-cli)
  - [Profilers & Analyzers](#profilers--analyzers)
  - [Low-Overhead / Native Profilers](#lowoverhead--native-profilers)
  - [Heap Dump & GC Log Analyzers](#heap-dump--gc-log-analyzers)
  - [Deep Agents & Bytecode Tools](#deep-agents--bytecode-tools)
  - [Object Sizing & Layout Libraries](#object-sizing--layout-libraries)
  - [Native/Off-Heap Diagnostics](#nativeoffheap-diagnostics)
  - [GC & Performance Testing Harnesses](#gc--performance-testing-harnesses)
  - [Remote Access & Dashboards](#remote-access--dashboards)
  - [Alternative JVMs / Vendor Tools](#alternative-jvms--vendor-tools)
  - [IDE-Integrated Profilers](#ideintegrated-profilers)
  - [Starter Command Snippets](#starter-command-snippets)
- [Tools & Libraries Reference Tables](#tools--libraries-reference-tables)
- [Summary](#summary)
- [License](#license)

---

## Bytes in Java

| Property       | Details                                   |
|----------------|-------------------------------------------|
| Type           | `byte` (8-bit signed integer)             |
| Range          | `-128` to `127`                           |
| Representation | Two’s complement                          |
| Examples       | `01001100₂ = 76₁₀`, `11111111₂ = -1₁₀`   |

Notes:
- In expressions, `byte` promotes to `int`. Cast back to `byte` if needed.
- Treat an 8-bit value as “unsigned byte” via masking: `int u = b & 0xFF;`.

---

## Bitwise Operations

| Operator | Name  | Effect                                        | Example                                              |
|----------|-------|-----------------------------------------------|------------------------------------------------------|
| `&`      | AND   | 1 only if both bits are 1                     | `0b01001100 & 0b00001111 = 0b00001100` → `12`       |
| `\|`     | OR    | 1 if either bit is 1                          | `0b01001100 \| 0b00001111 = 0b01001111` → `79`      |
| `^`      | XOR   | 1 if bits differ                              | `0b01001100 ^ 0b00001111 = 0b01000011` → `67`       |
| `~`      | NOT   | flips all bits                                | `~0b01001100 = 0b10110011` (two’s complement `-77`) |

---

## Shift Operators

| Operator | Name                    | Behavior                                                      |
|----------|-------------------------|---------------------------------------------------------------|
| `<<`     | Left shift              | Shifts left, fills with `0`                                   |
| `>>`     | Arithmetic right shift  | Shifts right, fills with sign bit (`0` for +, `1` for −)      |
| `>>>`    | Logical right shift     | Shifts right, fills with `0` (works on `int`/`long`)          |

Examples:
```java
byte a = 0b01001100; // 76
int left  = a << 1;  // 152 (0b10011000)
int right = a >> 2;  // 19  (0b00010011, sign-extended as int)
int u3    = (a & 0xFF) >>> 3; // logical right shift on promoted byte
```
Practical Applications

Flags and masks: pack booleans/bitfields.
```
final int READ=1, WRITE=2, EXEC=4;
int perms = READ | EXEC;
boolean canWrite = (perms & WRITE) != 0; // false
```

Graphics: ARGB extraction.
```
int pixel = 0xFF336699;
int red   = (pixel >> 16) & 0xFF; // 51
int green = (pixel >> 8)  & 0xFF; // 102
int blue  =  pixel        & 0xFF; // 153
```

Networking: parse protocol headers with shifts/masks.

Compression/Encryption: shifting, XOR, and rotations are standard primitives.

Performance: tight loops and data packing.

Objects ↔ Bytes

Yes, objects can be represented as bytes (serialization), modified, and deserialized—if you know the structure.

Java Serialization (example)
```
import java.io.*;
class Person implements Serializable {
  String name; int age;
  Person(String n, int a){ name=n; age=a; }
}

Person p = new Person("Max", 28);

// Serialize
var bos = new ByteArrayOutputStream();
try (var out = new ObjectOutputStream(bos)) { out.writeObject(p); }
byte[] bytes = bos.toByteArray();

// Deserialize
var bis = new ByteArrayInputStream(bytes);
try (var in = new ObjectInputStream(bis)) {
  Person copy = (Person) in.readObject();
}
```
Manual Binary Layout (predictable)
```
import java.nio.*;
ByteBuffer buf = ByteBuffer.allocate(100).order(ByteOrder.LITTLE_ENDIAN);
buf.putInt(28);
buf.put("Max".getBytes());
buf.flip();
int age = buf.getInt();
```

Notes:

# Professional Byte Manipulation Notes

-   Blindly flipping bits can corrupt structured data (headers/type
    info).
-   A single byte is small; use `byte[]` for object payloads.

## Professional Byte Manipulation Standard Java Toolbox

### Category: APIs / Methods

#### Bit/shift helpers

-   `&`, `|`, `^`, `~`, `<<`, `>>`, `>>>`
-   `Integer.rotateLeft`, `Integer.rotateRight`

#### Counts/zeroes

-   `Integer.bitCount`
-   `Integer.numberOfLeadingZeros`
-   `Integer.numberOfTrailingZeros`

#### Endian/byte swap

-   `Integer.reverseBytes`
-   `Short.reverseBytes`
-   `Long.reverseBytes`

#### Hex/Base64

-   `HexFormat` (Java 17+)
-   `Base64`

#### Hash/Checksum

-   `MessageDigest` (e.g., SHA-256)
-   `java.util.zip.CRC32`

#### Charsets

-   `StandardCharsets.UTF_8` and friends

#### Buffers

-   `ByteBuffer`
-   `ByteBuffer.allocateDirect`
-   `MappedByteBuffer`
-   `slice()`, `asIntBuffer()`

#### Streams

-   `DataInputStream`, `DataOutputStream` (big-endian, Java-specific
    UTF)

#### File I/O

-   `FileChannel.open`
-   `map` (memory-mapped files; zero-copy patching)

Examples:
```
var hex = java.util.HexFormat.of().withUpperCase();
String s = hex.formatHex(bytes);
byte[] raw = hex.parseHex("DEADBEEF");

var md = java.security.MessageDigest.getInstance("SHA-256");
byte[] digest = md.digest(bytes);
```

Standard Java toolbox (no deps)
Bit & byte helpers
```
// set/clear/test a bit
byte setBit(byte x, int i)   { return (byte)(x |   (1 << i)); }
byte clrBit(byte x, int i)   { return (byte)(x & ~(1 << i)); }
boolean isSet(byte x, int i) { return (x & (1 << i)) != 0; }

// rotate (works on int/long)
int rol(int x, int s) { return Integer.rotateLeft(x, s); }
int ror(int x, int s) { return Integer.rotateRight(x, s); }

// popcount, clz, ctz
int pc  = Integer.bitCount(v);
int nlz = Integer.numberOfLeadingZeros(v);
int ntz = Integer.numberOfTrailingZeros(v);

// endian swap
int swap = Integer.reverseBytes(v);     // short/long variants also exist

```
Hex/Base64

```
var hex = java.util.HexFormat.of().withUpperCase();
String s = hex.formatHex(bytes);
byte[] b = hex.parseHex("DEADBEEF");

String b64 = java.util.Base64.getEncoder().encodeToString(bytes);
byte[] raw = java.util.Base64.getDecoder().decode(b64);

```

Packing/unpacking with ByteBuffer
```
ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
buf.putInt(0x11223344).putShort((short)0xABCD);
buf.flip();
int v  = buf.getInt();       // 0x11223344 (little-endian)
int u8 = buf.get() & 0xFF;   // read a byte as unsigned

```

File I/O & zero-copy
```
try (var ch = FileChannel.open(path)) {
  MappedByteBuffer mm = ch.map(FileChannel.MapMode.READ_WRITE, 0, ch.size());
  int v = mm.getInt(128);
  mm.put(128, (byte)0x42);      // patch a single byte in-place
}

```
Data streams (simple binary protocols)
```
try (var out = new DataOutputStream(new ByteArrayOutputStream())) {
  out.writeInt(42); out.writeUTF("Max");
}
try (var in = new DataInputStream(new ByteArrayInputStream(bytes))) {
  int n = in.readInt(); String s = in.readUTF();
}
```

Checksums & hashes

```

var crc = new java.util.zip.CRC32();
crc.update(bytes); long v = crc.getValue();

var md = java.security.MessageDigest.getInstance("SHA-256");
byte[] digest = md.digest(bytes);

```
Charsets (bytes ↔ text)
```
byte[] utf8 = "Привіт".getBytes(StandardCharsets.UTF_8);
String s = new String(utf8, StandardCharsets.UTF_8);
```
###Advanced & “close to metal” Java
VarHandle (safe low-level primitives)

Fine-grained, volatile/atomic access to arrays, buffers, and fields.
```
VarHandle VH_BYTE = MethodHandles.arrayElementVarHandle(byte[].class);
byte x = (byte) VH_BYTE.getAcquire(arr, idx);
VH_BYTE.setRelease(arr, idx, (byte)123);

```
Panama Foreign Memory API (JDK 22+)

Off-heap structured memory with layouts; great for “C struct” style binary.

```
try (var arena = Arena.ofConfined()) {
  MemorySegment seg = arena.allocate(16);
  seg.set(ValueLayout.JAVA_INT, 0, 0xDEADBEEF);
  int v = seg.get(ValueLayout.JAVA_INT, 0);
}

```
Define MemoryLayout to pack/unpack complex structs with explicit endianness.

sun.misc.Unsafe (sharp knives)

Raw memory ops: allocate, copy, CAS.

Great power; JVM-dependent & non-portable. Prefer VarHandle/Panama unless you know why not.


Third-party power tools
High-performance byte containers

Netty ByteBuf: reference-counted, pooled, zero-copy slices/composites, endian aware.
```
ByteBuf buf = PooledByteBufAllocator.DEFAULT.buffer();
buf.writeIntLE(0x11223344);
int v = buf.readUnsignedByte();  // 0..255
ByteBuf slice = buf.slice(4, 8); // zero-copy view

```
Agrona DirectBuffer/MutableDirectBuffer: flyweight views over off-heap/heap memory.

Chronicle Bytes: off-heap bytes with random access, memory-mapped files, huge data logs.

Binary serialization / protocols

Protocol Buffers, FlatBuffers, Cap’n Proto, SBE (Simple Binary Encoding), Avro

Protobuf/Avro = schema-based, compact.

FlatBuffers/Cap’n Proto = zero-copy reads (no deserialization step).

SBE (Real-Logic) = finance-grade, low-latency, fixed layouts.

Kryo / Protostuff: fast general-purpose object serialization (not human-readable).

MessagePack / CBOR / BSON: compact binary JSON-likes.

Binary format parsers & DSLs

Kaitai Struct: write a .ksy spec of your binary format → auto-generates a Java parser.

JBBP (Java Bit-Byte Parser): parse bitfields and packed formats (e.g., “read 3 bits, then 13 bits…”).

Bitmaps & compressed bitsets

RoaringBitmap (and JavaEWAH): memory-efficient large sets of integers with fast bit-ops.

Compression / codecs

LZ4, Zstd, Snappy: high-speed compression on byte[]/ByteBuffer.

Brotli, GZIP/Deflate (stdlib) for web pipes.

Crypto

BouncyCastle: rich cryptography primitives and ciphers for byte-level transforms.

Native interop (when bytes meet C)

JNA/JNR-FFI (easy) or JNI (manual) to call native code and hand over byte[]/off-heap memory.
Practical recipes (copy-paste ready)
1) Pack structured fields manually (little-endian)
record Header(int magic, short version, short flags) {
  byte[] toBytes() {
    var bb = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
    bb.putInt(magic).putShort(version).putShort(flags);
    return bb.array();
  }
  static Header from(byte[] b) {
    var bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
    return new Header(bb.getInt(), bb.getShort(), bb.getShort());
  }
}

2) Treat bytes as unsigned
int b0 = bytes[i]   & 0xFF;
int b1 = bytes[i+1] & 0xFF;
int u16 = (b1 << 8) | b0;          // little-endian unsigned 16-bit
long u32 = ((long)b3 << 24) | ((long)b2 << 16) | ((long)b1 << 8) | b0;

3) Bitfields in an int
// layout: [unused:8][type:4][flags:4][len:16]
int pack(int len, int flags, int type) {
  return ((type & 0xF) << 20) | ((flags & 0xF) << 16) | (len & 0xFFFF);
}
int len   = v & 0xFFFF;
int flags = (v >>> 16) & 0xF;
int type  = (v >>> 20) & 0xF;

4) Parse/patch a memory-mapped file
try (var ch = FileChannel.open(path, READ, WRITE)) {
  var map = ch.map(FileChannel.MapMode.READ_WRITE, 0, ch.size()).order(ByteOrder.BIG_ENDIAN);
  int header = map.getInt(0);
  map.put(0, (byte)0x7F);              // patch 1st byte of header
  map.force();                         // flush to disk
}

5) Zero-copy slicing with Netty ByteBuf
ByteBuf all   = Unpooled.wrappedBuffer(bytes);
ByteBuf head  = all.slice(0, 16);     // view, no copy
ByteBuf body  = all.slice(16, all.readableBytes()-16);
int magic = head.readInt();

6) Fast rotate/xor (crypto-style mixing)
int mix(int x, int y) {
  x ^= Integer.rotateLeft(y, 13);
  y ^= Integer.rotateLeft(x, 7);
  return x ^ y;
}

7) Panama “struct” with explicit layout (JDK 22+)
static final ValueLayout.OfInt I32 = ValueLayout.JAVA_INT.withOrder(ByteOrder.LITTLE_ENDIAN);

try (var arena = Arena.ofConfined()) {
  MemorySegment seg = arena.allocate(12);
  seg.set(I32, 0, 0xCAFEBABE);
  seg.set(I32, 4, 42);
  seg.set(I32, 8, 7);
  int v = seg.get(I32, 4);
}

When to use what (decision guide)

Simple packing/unpacking: ByteBuffer + masks/shifts.

Huge files / patching bytes in place: MappedByteBuffer.

High-throughput I/O, zero-copy, pooling: Netty ByteBuf.

Low-latency fixed schemas (trading, telemetry): SBE, Agrona.

Cross-lang APIs: Protobuf / FlatBuffers / Cap’n Proto.

Binary format reverse-engineering: Kaitai Struct or JBBP.

Off-heap structured memory without JNI: Panama.

Absolute max control / hacks: Unsafe (last resort).

Pitfalls & pro tips

Always mask when converting byte → int: b & 0xFF.

Be explicit about endianness everywhere.

Avoid copying: prefer slices/views (ByteBuffer slice(), Netty slice() / retainedSlice()).

Watch alignment & atomicity if you share memory across threads/devices; use VarHandle/Panama with acquire/release/opaque modes when needed.

Benchmark with JMH; intuitive “fast” code often isn’t.

For security, avoid home-rolled crypto. Use proven libs (BouncyCastle, JCA).


Heap inspection (objects in memory)

Runtime API

long free  = Runtime.getRuntime().freeMemory();
long total = Runtime.getRuntime().totalMemory();
long max   = Runtime.getRuntime().maxMemory();


→ Gives JVM heap usage, not per-object detail.

java.lang.instrument.Instrumentation

Add an agent to your app and call:

long size = instrumentation.getObjectSize(obj);


Only gives shallow size. For deep size (all referenced objects), you need third-party libs.

Libraries for object sizing:

JOL (Java Object Layout) — from OpenJDK, inspects how objects are laid out in memory.

System.out.println(ClassLayout.parseInstance(obj).toPrintable());


Output: header, field offsets, padding, alignment.

Jamm (Java Agent for Memory Measurements) — measures object graph sizes.

Stack inspection

Thread stacks are not in the heap; each thread gets its own stack (by default ~1MB).

You can inspect them with:

Map<Thread, StackTraceElement[]> all = Thread.getAllStackTraces();
for (Map.Entry<Thread, StackTraceElement[]> e : all.entrySet()) {
    System.out.println(e.getKey().getName());
    for (StackTraceElement ste : e.getValue()) {
        System.out.println("  " + ste);
    }
}


For a single thread:

Thread.dumpStack();


JVMTI / Debug Attach: deeper introspection (native agent or tools like JFR).

🛠 2. From outside (tools you run on the JVM)
JVM-native tools

jmap

jmap -heap <pid> → prints heap summary (eden/survivor/old gen).

jmap -histo <pid> → histogram of object counts/sizes by class.

jmap -dump:live,file=heap.bin <pid> → full heap dump file.

jstack

jstack <pid> → dump all thread stacks.

jcmd

General-purpose swiss knife. Examples:

jcmd <pid> GC.heap_info

jcmd <pid> Thread.print

jcmd <pid> GC.class_histogram

jconsole / VisualVM

GUIs bundled with the JDK. Show heap graphs, threads, GC, class histograms.

Modern profilers

VisualVM (ships with JDK, free). Heap dump browsing, thread monitoring, CPU profiler.

Java Mission Control (JMC) + Flight Recorder (JFR) (Oracle/OpenJDK). Low-overhead profiling, heap allocations, GC, threads.

Async Profiler — super fast native sampling profiler.

YourKit / JProfiler (commercial) — heavy-duty heap & thread analyzers.

📦 3. Advanced APIs / Libraries

JOL (Java Object Layout)
See per-field memory layout.

import org.openjdk.jol.info.ClassLayout;
System.out.println(ClassLayout.parseClass(MyClass.class).toPrintable());


JMH (Java Microbenchmark Harness)
Measures allocations & GC in tight loops with -prof gc.

Unsafe / VarHandle (not recommended, but possible)
You can peek into raw memory offsets of objects with sun.misc.Unsafe, but that’s risky.

Panama Foreign Memory API (JDK 22+)
For off-heap structures, not the managed heap.

1) From inside your Java code (standard APIs)
Memory & GC

Runtime.getRuntime().{free,total,max}Memory() — coarse heap sizes.

MXBeans (JMX) via ManagementFactory:

MemoryMXBean, MemoryPoolMXBean — heap pools (Eden/Survivor/Old, Metaspace).

GarbageCollectorMXBean — GC counts & times.

BufferPoolMXBean — direct buffer counts/bytes.

ThreadMXBean — thread counts, CPU, deadlocks.

Stack inspection

Thread.getAllStackTraces() / Thread.dumpStack()

ThreadMXBean.dumpAllThreads(...)

StackWalker (Java 9+) — fast, flexible current-thread stack access.

Object size/layout (in-process)

JOL (Java Object Layout) — field offsets, headers, padding, alignment.

java.lang.instrument.Instrumentation — getObjectSize(obj) (shallow).

For deep size: libraries below (Jamm, RamUsageEstimator, etc.).

Panama Foreign Memory API (JDK 22+) — not for heap inspection, but for controlled off-heap structures you define (great for precise memory experiments).

VarHandle — low-level, atomic/ordered access to arrays/fields (useful for building inspectors).

2) Built-in JDK tools (CLI)

jcmd — Swiss-army knife:

GC.heap_info, GC.class_histogram, GC.heap_dump

VM.native_memory summary (if NMT enabled)

Thread.print

JFR.start|dump|stop

jmap — heap summary, histograms, dumps: jmap -histo, -dump:live,file=...

jstack — all thread stacks (blocked/runnable states).

jstat — GC and class loader stats over time.

jinfo — JVM flags at runtime.

jhsdb (Serviceability Agent) — deep post-mortem or live attach:

jhsdb clhsdb, jhsdb jmap, jhsdb jstack (works even when JVM is wedged).

jconsole / VisualVM launcher — simple GUI monitors.

jfr (JDK tool) — manipulate Flight Recorder files.

GC logging (JDK 9+): -Xlog:gc*,safepoint,class+unload=info:file=gc.log:tags,uptime,level → analyze with tools below.

Tips:

Enable NMT (Native Memory Tracking) to inspect native allocations: -XX:NativeMemoryTracking=summary|detail, then jcmd <pid> VM.native_memory.

OOM dumps automatically: -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=...

3) GUI profilers & analyzers
Free / Open Source

Java Flight Recorder (JFR) + Java Mission Control (JMC) — low-overhead, prod-safe allocations, GC, threads, locks, I/O.

VisualVM — heap sampler, CPU profiler, heap dump browser, thread view.

Eclipse MAT (Memory Analyzer Tool) — heap dump deep dive (dominator tree, leak suspects).

GCViewer — chart & analyze GC logs.

Commercial (powerful & polished)

YourKit Java Profiler — CPU, memory, allocations, snapshots, threads, probes.

JProfiler — similar full-stack profiler.

AppDynamics / Dynatrace / New Relic / Datadog APM — production telemetry & heap snapshots / allocation profiling (vary by product).

Container/JFR specific

Cryostat (ContainerJFR) — manage JFR on Kubernetes/containers.

4) Low-overhead/native profilers

async-profiler — gold standard native sampler:

CPU, allocations, locks, wall-clock, memleaks (arena), OS-level stacks.

Produces flame graphs / JFR output.

Honest Profiler — older async sampling.

perf + perf-map-agent (Linux) — system profiler; map Java symbols.

FlameGraph (Brendan Gregg) — render flame graphs from stacks.

5) Heap dump & GC log web analyzers

Eclipse MAT (desktop) — primary choice for dumps.

HeapHero / GCeasy / yCrash / fastThread — upload GC logs/heap dumps; get reports.

HPJMeter / IBM PMAT — older but still seen in enterprise GC analysis ecosystems.

6) Deep agents & bytecode tools (instrument anything)

java.lang.instrument — write agents to measure allocations, sizes, stacks at hotspots.

Byte Buddy — instrumentation with clean API (on top of ASM).

ASM — raw bytecode engineering.

BTrace — dynamic tracing via scripts, prints live data/stacks.

Byteman — rule-based bytecode injection for tracing/testing.

JFR Event Streaming — emit custom events, subscribe to live allocations/latency.

Legacy: HPROF (deprecated), don’t start new work with it.

7) Object sizing & layout (3rd-party)

JOL (OpenJDK) — definitive layout tool.

Jamm — agent for accurate sizeof across object graphs.

Carrotsearch SizeOf (com.carrotsearch.sizeof.RamUsageEstimator) — used in Lucene; estimates retained sizes.

Lucene’s RamUsageEstimator — handy utility if you already depend on Lucene.

8) Native memory / off-heap diagnostics

NMT (see above) — first stop for native memory mysteries.

DirectBuffer accounting — BufferPoolMXBean via JMX.

Panama — when you own off-heap layout; measure precisely.

jemalloc/tdb/malloc hooks — if your distro links JVM to custom allocators (advanced).

GDB/lldb + SA — post-mortem native dumps (hardcore).

9) GC & performance testing harnesses

JMH — microbenchmarks; with -prof gc for allocation rates & GC counts.

JUnit + JFR — scenario tests that record JFR and assert allocation budgets.

Caliper (old), JMH is the modern standard.

10) Remote access & dashboards

JMX remote (SSL/RMI) — wire up VisualVM/JMC remotely.

Jolokia — JMX over HTTP/JSON (great in containers).

Micrometer + Prometheus/Grafana — expose heap, GC, threads, classloading metrics.

11) Alternative JVMs / vendor tools

OpenJ9: jdmpview, IBM Memory Analyzer integrations, extensions to NMT-like reports.

Azul/Zing/Zulu: vendor-specific GC diagnostics (C4), Mission Control integrations.

SAP Machine: generally compatible; often just use JDK tools.

12) IDE-integrated profilers

IntelliJ Profiler — wraps async-profiler/JFR, flame graphs, allocations.

NetBeans Profiler / VisualVM plugin — integrated lightweight profiling.

Eclipse MAT + Eclipse IDE — convenient for dump analysis in the workspace.

13) What to use, when (cheat-sheet)

“What’s in my heap right now?”
jcmd GC.class_histogram → class sizes; then heap dump → MAT.

“Why am I allocating so much?”
JFR (alloc events) or async-profiler alloc → flame graph by allocation site.

“What’s leaking?”
Heap dump → MAT dominator tree & leak suspects.

“Where’s native memory going?”
Enable NMT → jcmd VM.native_memory summary|detail.

“Thread deadlock/contention?”
jcmd Thread.print, JFR locks, or async-profiler locks.

“Prod-safe continuous insights?”
JFR + JMC (low overhead), optionally Micrometer/JMX dashboards.

“I need to instrument a specific class/method live.”
Byte Buddy agent or BTrace/Byteman rule.

14) Starter command snippets
# Heap histogram (top 50)
jcmd $PID GC.class_histogram | head -n 60

# Live heap dump
jcmd $PID GC.heap_dump /tmp/heap.hprof

# GC/heap quick info
jcmd $PID GC.heap_info

# Native memory (enable with -XX:NativeMemoryTracking=summary)
jcmd $PID VM.native_memory summary

# All thread stacks
jcmd $PID Thread.print > /tmp/threads.txt
jstack $PID > /tmp/threads.txt

# Start JFR for 2 minutes and dump
jcmd $PID JFR.start name=diag settings=profile filename=/tmp/run.jfr duration=2m

15) Gotchas & best practices

Always label environments: prod vs local (flags/overhead).

Prefer JFR/async-profiler for low-overhead, accurate signals.

Don’t trust “shallow size” when chasing leaks — use retained size in MAT.

Turn on NMT early if native leaks are suspected; it can’t retroactively help.

Keep symbols (HotSpot hsdis optional) if you dig into assembly; not required for most work.

Automate: build small scripts to capture JFR, histograms, thread dumps on incident.

















Advanced Low-Level APIs
API	Purpose
VarHandle	Safe, fine-grained, ordered/atomic access to array elements and fields
Foreign Memory (Panama; JDK 22+)	Off-heap segments, explicit layouts, and endianness
sun.misc.Unsafe	Raw memory ops; non-portable; last resort

Panama example:
```
import java.lang.foreign.*;
import java.nio.ByteOrder;
import static java.lang.foreign.ValueLayout.*;

try (Arena arena = Arena.ofConfined()) {
  MemorySegment seg = arena.allocate(12);
  var I32LE = JAVA_INT.withOrder(ByteOrder.LITTLE_ENDIAN);
  seg.set(I32LE, 0, 0xCAFEBABE);
  seg.set(I32LE, 4, 42);
  int v = seg.get(I32LE, 4);
}
```
Third-Party Power Tools
Purpose	Libraries / Tools
High-perf byte containers	: Netty ByteBuf, Agrona DirectBuffer, Chronicle Bytes
Binary serialization	Protocol Buffers, FlatBuffers, Cap’n Proto, Avro, Kryo, Protostuff
Compact binary JSON-likes	MessagePack, CBOR, BSON
Binary parsing DSLs	Kaitai Struct, JBBP
Bitmaps / compressed sets	RoaringBitmap, JavaEWAH
Compression	LZ4, Zstd, Snappy, Brotli, GZIP/Deflate
Cryptography	BouncyCastle
Native interop	JNI (manual), JNA/JNR-FFI (simpler)

Netty example:
```
import io.netty.buffer.*;
ByteBuf buf = PooledByteBufAllocator.DEFAULT.buffer();
buf.writeIntLE(0x11223344);
int u8 = buf.readUnsignedByte();
ByteBuf slice = buf.slice(4, 8); // zero-copy view

Practical Recipes

Pack structured fields (little-endian)

record Header(int magic, short version, short flags) {
  byte[] toBytes() {
    var bb = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
    bb.putInt(magic).putShort(version).putShort(flags);
    return bb.array();
  }
  static Header from(byte[] b) {
    var bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
    return new Header(bb.getInt(), bb.getShort(), bb.getShort());
  }
}

```
Unsigned reads and multi-byte assembly
```
int b0 = bytes[i]   & 0xFF;
int b1 = bytes[i+1] & 0xFF;
int u16 = (b1 << 8) | b0; // little-endian

```
Bitfields in an int

// layout: [unused:8][type:4][flags:4][len:16]
```
int pack(int len, int flags, int type) {
  return ((type & 0xF) << 20) | ((flags & 0xF) << 16) | (len & 0xFFFF);
}
int len   = v & 0xFFFF;
int flags = (v >>> 16) & 0xF;
int type  = (v >>> 20) & 0xF;

```
Memory-mapped file patch
```
try (var ch = java.nio.file.Files.newByteChannel(path,
       java.util.Set.of(java.nio.file.StandardOpenOption.READ,
                        java.nio.file.StandardOpenOption.WRITE))) {
  var map = ((java.nio.channels.FileChannel) ch)
            .map(java.nio.channels.FileChannel.MapMode.READ_WRITE, 0, ((java.nio.channels.FileChannel) ch).size())
            .order(ByteOrder.BIG_ENDIAN);
  int header = map.getInt(0);
  map.put(0, (byte)0x7F);
}

```
Crypto-style mixing (rotate/xor)
```
int mix(int x, int y) {
  x ^= Integer.rotateLeft(y, 13);
  y ^= Integer.rotateLeft(x, 7);
  return x ^ y;
}
```
Decision Guide

Simple pack/unpack: ByteBuffer + masks/shifts.

Huge files / in-place patching: MappedByteBuffer.

High-throughput I/O and pooling: Netty ByteBuf.

Low-latency fixed schemas: SBE (Simple Binary Encoding), Agrona.

Cross-language APIs: Protobuf / FlatBuffers / Cap’n Proto.

Reverse-engineering unknown binary formats: Kaitai Struct or JBBP.

Off-heap with explicit layout, no JNI: Panama.

Max control / hacks: Unsafe (avoid unless necessary).

Pitfalls & Pro Tips

Always mask when converting byte → int: b & 0xFF.

Be explicit about endianness.

Prefer slices/views over copies (ByteBuffer.slice(), ByteBuf.slice()).

For concurrency, use VarHandle acquire/release/opaque modes appropriately.

Benchmark with JMH; intuition is unreliable.

Avoid home-rolled crypto; use JCA/BouncyCastle.

Heap & Stack Inspection
From Inside Your Code
Area	APIs / Libraries
Heap size	Runtime.getRuntime().{free,total,max}Memory()
MXBeans (JMX)	MemoryMXBean, MemoryPoolMXBean, GarbageCollectorMXBean, BufferPoolMXBean, ThreadMXBean
Stacks	Thread.getAllStackTraces(), Thread.dumpStack(), StackWalker
Object size/layout	java.lang.instrument.Instrumentation#getObjectSize (shallow), JOL (layout), Jamm (retained)
Off-heap experiments	Panama (Foreign Memory API)
Low-level access	VarHandle; Unsafe (discouraged)
Built-in JDK Tools (CLI)
Tool	Purpose / Examples
jcmd	GC.heap_info, GC.class_histogram, GC.heap_dump, Thread.print, VM.native_memory (with NMT), `JFR.start
jmap	Heap summary, histograms, dumps: jmap -histo <pid>, jmap -dump:live,file=heap.hprof <pid>
jstack	All thread stacks: jstack <pid>
jstat	GC/class loader stats over time
jinfo	View JVM flags at runtime
jhsdb	Serviceability Agent frontends: deep live/post-mortem (clhsdb, jmap, jstack)
jconsole / VisualVM launcher	Lightweight GUI monitors
jfr	Manage Flight Recorder files

GC logging (JDK 9+):

-Xlog:gc*,safepoint,class+unload=info:file=gc.log:tags,uptime,level


Enable Native Memory Tracking (NMT):

-XX:NativeMemoryTracking=summary
# then:
jcmd <pid> VM.native_memory summary


Automatic heap dump on OOM:

-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/heap.hprof

Profilers & Analyzers

Free/Open Source: VisualVM; Java Flight Recorder (JFR) + Java Mission Control (JMC); Eclipse MAT; GCViewer.

Commercial: YourKit, JProfiler.

Container/JFR orchestration: Cryostat (ContainerJFR).

Low-Overhead / Native Profilers

async-profiler (CPU, allocations, locks, wall-clock; flame graphs; JFR output).

Honest Profiler (older).

Linux perf + perf-map-agent.

FlameGraph (post-processing).

Heap Dump & GC Log Analyzers

Eclipse MAT (desktop): dominator tree, leak suspects.

HeapHero, GCeasy, yCrash, fastThread (web analyzers).

HPJMeter / IBM PMAT (legacy enterprise GC tooling).

Deep Agents & Bytecode Tools

java.lang.instrument agents (measure allocations, sizes).

Byte Buddy (high-level instrumentation), ASM (low-level bytecode).

BTrace (dynamic tracing), Byteman (rule-based injection).

JFR Event Streaming (emit/consume custom events).

HPROF (deprecated; avoid for new work).

Object Sizing & Layout Libraries

JOL (Java Object Layout): field offsets, headers, padding, alignment.

Jamm (agent; retained sizes).

Carrotsearch SizeOf / Lucene’s RamUsageEstimator.

Native/Off-Heap Diagnostics

NMT (Native Memory Tracking).

Direct buffer accounting via BufferPoolMXBean.

Panama for controlled off-heap layouts.

GDB/lldb + Serviceability Agent for post-mortem native dumps (advanced).

GC & Performance Testing Harnesses

JMH (Java Microbenchmark Harness), with -prof gc for allocation/GC counts.

JUnit + JFR (scenario tests with allocation budgets).

Caliper (legacy; prefer JMH).

Remote Access & Dashboards

JMX remote (SSL/RMI) to connect VisualVM/JMC.

Jolokia (JMX over HTTP/JSON).

Micrometer + Prometheus + Grafana (heap, GC, threads, classloading metrics).

Alternative JVMs / Vendor Tools

OpenJ9: jdmpview, IBM MAT integrations.

Azul (Zing/Zulu): vendor GC diagnostics (e.g., C4), JMC integrations.

SAP Machine: generally compatible with HotSpot tooling.

IDE-Integrated Profilers

IntelliJ Profiler (wraps async-profiler/JFR; flame graphs, allocations).

NetBeans Profiler (VisualVM-based).

Eclipse + MAT integration.

Starter Command Snippets
# Heap histogram (top 50)
jcmd $PID GC.class_histogram | head -n 60

# Live heap dump
jcmd $PID GC.heap_dump /tmp/heap.hprof

# GC/heap quick info
jcmd $PID GC.heap_info

# Native memory (with NMT)
jcmd $PID VM.native_memory summary

# All thread stacks
jcmd $PID Thread.print > /tmp/threads.txt
jstack $PID > /tmp/threads.txt

# Start a JFR for 2 minutes and dump
jcmd $PID JFR.start name=diag settings=profile filename=/tmp/run.jfr duration=2m

Tools & Libraries Reference Tables
Bitwise, Shifts, Counts
Item	Notes
&, |, ^, ~, <<, >>, >>>	Core operators
Integer.rotateLeft/Right	Rotations for mixing/crypto-style ops
Integer.bitCount	Population count
Integer.numberOfLeadingZeros/TrailingZeros	Bit scans
Conversions, Checksums, Encodings
Item	Notes
HexFormat	Hex encode/decode
Base64	Standard Base64 encode/decode
MessageDigest	SHA-256 and others
CRC32	Fast checksums
StandardCharsets	Correct text ↔ bytes
Buffers and I/O
Item	Notes
ByteBuffer	Heap/direct buffers; endian control
MappedByteBuffer	Memory-mapped files; zero-copy patching
FileChannel	map, random access
DataInput/OutputStream	Simple binary protocols (big-endian)
Advanced Memory and Unsafe
Item	Notes
VarHandle	Ordered/atomic field/array access
Panama	Off-heap segments, explicit MemoryLayout
Unsafe	Raw memory (non-portable; last resort)
Serialization and Binary Protocols
Category	Libraries
Schema-based	Protocol Buffers, Avro, SBE
Zero-copy reading	FlatBuffers, Cap’n Proto
General-purpose	Kryo, Protostuff
Binary JSON-likes	MessagePack, CBOR, BSON
Byte Containers, Parsing DSLs, Bitsets
Category	Libraries
Byte containers	Netty ByteBuf, Agrona, Chronicle
Parsing DSLs	Kaitai Struct, JBBP
Bitsets	RoaringBitmap, JavaEWAH
Compression and Crypto
Category	Libraries
Compression	LZ4, Zstd, Snappy, Brotli, GZIP
Crypto	BouncyCastle
Profiling, Heap, GC, Thread Tools
Category	Tools
JDK CLI	jcmd, jmap, jstack, jstat, jinfo, jhsdb, jfr
GC Logging	-Xlog:gc* flags
NMT	`-XX:NativeMemoryTracking=summary
Free GUIs	VisualVM, JMC (with JFR), Eclipse MAT, GCViewer
Commercial	YourKit, JProfiler
Native profilers	async-profiler, Honest Profiler, Linux perf, FlameGraph
Web analyzers	HeapHero, GCeasy, yCrash, fastThread
Agents/bytecode	Byte Buddy, ASM, BTrace, Byteman, JFR Event Streaming
Monitoring	JMX, Jolokia, Micrometer, Prometheus, Grafana
IDE profilers	IntelliJ Profiler, NetBeans Profiler
Alternative JVMs	OpenJ9 (jdmpview), Azul/C4 tooling, SAP Machine
Summary

Byte manipulation: master masks, shifts, rotations, endian handling, and buffer views.

Objects ↔ bytes: use serialization or explicit binary layouts; modify only with structural awareness.

Advanced control: VarHandle and Panama provide safe low-level primitives; Unsafe is a last resort.

Observability: combine in-process MXBeans/JFR with jcmd/heap dumps and profilers (VisualVM, JMC, async-profiler, MAT).

Ecosystem: choose the right tool—Netty/Agrona/Chronicle for bytes, Protobuf/FlatBuffers/SBE for protocols, Kaitai/JBBP for parsing, RoaringBitmap for sets, LZ4/Zstd for speed, BouncyCastle for crypto.
