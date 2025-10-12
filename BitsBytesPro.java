import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;

/**
 * BitsBytesPro - All-in-one byte/bit/format conversion suite (CLI + library).
 *
 * Build:
 *   javac BitsBytesPro.java
 *
 * Quick uses:
 *   # From a literal string
 *   java BitsBytesPro --str "Hello Bits!" --dump --json --md --b64
 *
 *   # From a file, write multiple outputs (auto filenames)
 *   java BitsBytesPro --in sample.bin --dump --json --yaml --csv --tsv --md --html --b64 --b32 --c --java --py --go
 *
 *   # STDIN to STDOUT dump (pipe)
 *   cat sample.bin | java BitsBytesPro --stdin --dump
 *
 * Library usage:
 *   String md = BitsBytesPro.Format.markdownTable(bytes);
 *   String hex = BitsBytesPro.Dump.hexDump(bytes, 0, 16, true);
 *   int flags = BitsBytesPro.Bits.getBits(0b101101, 1, 3); // -> 0b110
 */
public class BitsBytesPro {

    /* =========================================================
     * ===============  CLI ENTRYPOINT & OPTIONS  ===============
     * ========================================================= */
    public static void main(String[] args) {
        try {
            CliOptions opt = CliOptions.parse(args);
            byte[] data = loadInput(opt);
            if (data == null) {
                System.err.println("No input provided. Use --in <file>, --str <text>, or --stdin.");
                System.exit(2);
                return;
            }
            runSelectedOutputs(opt, data);
        } catch (IllegalArgumentException iae) {
            System.err.println("Argument error: " + iae.getMessage());
            System.err.println(CliOptions.usage());
            System.exit(2);
        } catch (IOException ioe) {
            System.err.println("I/O error: " + ioe.getMessage());
            System.exit(1);
        }
    }

    private static byte[] loadInput(CliOptions opt) throws IOException {
        if (opt.stdin) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int r;
            while ((r = System.in.read(buf)) != -1) bos.write(buf, 0, r);
            return bos.toByteArray();
        }
        if (opt.inFile != null) return Files.readAllBytes(new File(opt.inFile).toPath());
        if (opt.literalString != null) return opt.literalString.getBytes("UTF-8");
        return null;
    }

    private static void runSelectedOutputs(CliOptions opt, byte[] data) throws IOException {
        // hexdump
        if (opt.dump) {
            String s = Dump.hexDump(data, 0, opt.bytesPerLine, true);
            emit(opt, s, ".dump.txt");
        }
        if (opt.binTable) {
            String s = Dump.binaryTable(data, 0, opt.bytesPerLine);
            emit(opt, s, ".bintable.txt");
        }
        if (opt.octGrid) {
            String s = Dump.octalGrid(data, 0, opt.bytesPerLine);
            emit(opt, s, ".octgrid.txt");
        }
        if (opt.decGrid) {
            String s = Dump.decimalGrid(data, 0, opt.bytesPerLine);
            emit(opt, s, ".decgrid.txt");
        }

        // structured formats
        if (opt.json) emit(opt, Format.json(data), ".json");
        if (opt.yaml) emit(opt, Format.yaml(data), ".yaml");
        if (opt.csv)  emit(opt, Format.csv(data, true), ".csv");
        if (opt.tsv)  emit(opt, Format.tsv(data, true), ".tsv");
        if (opt.md)   emit(opt, Format.markdownTable(data), ".md");
        if (opt.html) emit(opt, Format.htmlTable(data), ".html");

        // encodings
        if (opt.b64) emit(opt, Encoding.base64(data), ".b64.txt");
        if (opt.b32) emit(opt, Encoding.base32(data), ".b32.txt");

        // language literals
        if (opt.cArr)    emit(opt, Lang.cArray(data, "data"), ".c.txt");
        if (opt.javaArr) emit(opt, Lang.javaByteArray(data, "data"), ".java.txt");
        if (opt.pyBytes) emit(opt, Lang.pythonBytes(data, "data"), ".py.txt");
        if (opt.goSlice) emit(opt, Lang.goByteSlice(data, "data"), ".go.txt");

        // if nothing chosen, default to hexdump
        if (opt.nothingChosen()) {
            String s = Dump.hexDump(data, 0, opt.bytesPerLine, true);
            emit(opt, s, ".dump.txt");
        }
    }

    private static void emit(CliOptions opt, String content, String defaultSuffix) throws IOException {
        if (opt.outPrefix == null) {
            System.out.println(content);
            System.out.flush();
        } else {
            String base = (opt.inFile != null ? opt.inFile : "stdin");
            String name = base + defaultSuffix;
            String out = opt.outPrefix.isEmpty() ? name : opt.outPrefix + defaultSuffix;
            try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
                pw.print(content);
            }
            System.err.println("Wrote: " + out);
        }
    }

    /* =========================================================
     * ======================  CLI PARSER  ======================
     * ========================================================= */
    static class CliOptions {
        String inFile = null;
        String literalString = null;
        boolean stdin = false;

        boolean dump = false;
        boolean binTable = false;
        boolean octGrid = false;
        boolean decGrid = false;

        boolean json = false, yaml = false, csv = false, tsv = false, md = false, html = false;
        boolean b64 = false, b32 = false;

        boolean cArr = false, javaArr = false, pyBytes = false, goSlice = false;

        String outPrefix = null;   // if set, write files (prefix or empty uses default base name)
        int bytesPerLine = 16;

        static String usage() {
            return String.join("\n",
                "BitsBytesPro - byte/bit conversion & dumps",
                "Usage:",
                "  java BitsBytesPro (--in <file> | --str <text> | --stdin) [formats] [--out <prefix>] [--bpl <n>]",
                "",
                "Inputs:",
                "  --in <file>       Read bytes from file",
                "  --str <text>      Read bytes from UTF-8 literal string",
                "  --stdin           Read bytes from STDIN",
                "",
                "Formats (choose any):",
                "  --dump            Hexdump with ASCII (xxd style)",
                "  --bin             Binary table (offset + 8-bit columns)",
                "  --oct             Octal grid (offset + octets)",
                "  --dec             Decimal grid",
                "  --json --yaml     Structured records per byte",
                "  --csv  --tsv      Columnar exports",
                "  --md   --html     Markdown/HTML tables",
                "  --b64  --b32      Base64/Base32 encodings",
                "  --c    --java     C uint8_t[] / Java byte[] literals",
                "  --py   --go       Python bytes / Go []byte",
                "",
                "Options:",
                "  --out <prefix>    Write each format to a separate file using this prefix",
                "                    (if empty string \"\", auto-name from input file base)",
                "  --bpl <n>         Bytes per line (default 16) for dump/grids",
                "",
                "Examples:",
                "  java BitsBytesPro --str \"Hello\" --dump --json",
                "  java BitsBytesPro --in file.bin --dump --md --b64 --out result",
                "  cat file.bin | java BitsBytesPro --stdin --dump --bpl 32"
            );
        }

        static CliOptions parse(String[] args) {
            CliOptions o = new CliOptions();
            if (args.length == 0) throw new IllegalArgumentException(usage());

            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "--in":   o.inFile = need(args, ++i, "--in requires a file path"); break;
                    case "--str":  o.literalString = need(args, ++i, "--str requires a text"); break;
                    case "--stdin": o.stdin = true; break;

                    case "--dump": o.dump = true; break;
                    case "--bin":  o.binTable = true; break;
                    case "--oct":  o.octGrid = true; break;
                    case "--dec":  o.decGrid = true; break;

                    case "--json": o.json = true; break;
                    case "--yaml": o.yaml = true; break;
                    case "--csv":  o.csv = true; break;
                    case "--tsv":  o.tsv = true; break;
                    case "--md":   o.md = true; break;
                    case "--html": o.html = true; break;

                    case "--b64":  o.b64 = true; break;
                    case "--b32":  o.b32 = true; break;

                    case "--c":    o.cArr = true; break;
                    case "--java": o.javaArr = true; break;
                    case "--py":   o.pyBytes = true; break;
                    case "--go":   o.goSlice = true; break;

                    case "--out":  o.outPrefix = need(args, ++i, "--out requires a prefix (\"\" allowed)"); break;
                    case "--bpl":  o.bytesPerLine = Integer.parseInt(need(args, ++i, "--bpl requires integer")); break;

                    case "--help":
                    case "-h":
                        throw new IllegalArgumentException(usage());
                    default:
                        throw new IllegalArgumentException("Unknown arg: " + a + "\n\n" + usage());
                }
            }
            if (o.inFile != null && o.stdin) throw new IllegalArgumentException("Use only one of --in or --stdin.");
            if (o.inFile != null && o.literalString != null) throw new IllegalArgumentException("Use only one of --in or --str.");
            return o;
        }

        boolean nothingChosen() {
            return !(dump || binTable || octGrid || decGrid || json || yaml || csv || tsv || md || html || b64 || b32 || cArr || javaArr || pyBytes || goSlice);
        }

        static String need(String[] args, int idx, String msg) {
            if (idx >= args.length) throw new IllegalArgumentException(msg);
            return args[idx];
        }
    }

    /* =========================================================
     * =====================  DUMP PRINTERS  ===================
     * ========================================================= */
    public static class Dump {
        private static final Pattern PRINTABLE = Pattern.compile("[\\x20-\\x7E]");

        public static String hexDump(byte[] data, int offset, int bytesPerLine, boolean showAscii) {
            StringBuilder sb = new StringBuilder();
            int n = data.length;
            for (int i = 0; i < n; i += bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, n - i);
                // Offset
                sb.append(String.format("%08X  ", i + offset));
                // Hex octets
                for (int j = 0; j < bytesPerLine; j++) {
                    if (j < lineLen) {
                        sb.append(String.format("%02X", data[i + j]));
                    } else {
                        sb.append("  ");
                    }
                    if (j % 2 == 1) sb.append(' ');
                }
                if (showAscii) {
                    sb.append(" |");
                    for (int j = 0; j < lineLen; j++) {
                        int v = data[i + j] & 0xFF;
                        char c = (v >= 0x20 && v <= 0x7E) ? (char) v : '.';
                        sb.append(c);
                    }
                    sb.append('|');
                }
                sb.append('\n');
            }
            return sb.toString();
        }

        public static String binaryTable(byte[] data, int offset, int bytesPerLine) {
            StringBuilder sb = new StringBuilder();
            sb.append("Offset    ");
            for (int b = 7; b >= 0; b--) sb.append(' ').append(b);
            sb.append('\n');
            for (int i = 0; i < data.length; i += bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, data.length - i);
                for (int j = 0; j < lineLen; j++) {
                    byte val = data[i + j];
                    sb.append(String.format("%08X  ", i + j + offset));
                    for (int bit = 7; bit >= 0; bit--) {
                        sb.append(' ').append(((val >> bit) & 1));
                    }
                    sb.append('\n');
                }
            }
            return sb.toString();
        }

        public static String octalGrid(byte[] data, int offset, int bytesPerLine) {
            StringBuilder sb = new StringBuilder();
            sb.append("Offset    Octets (base 8)\n");
            for (int i = 0; i < data.length; i += bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, data.length - i);
                sb.append(String.format("%08X  ", i + offset));
                for (int j = 0; j < lineLen; j++) {
                    sb.append(String.format("%03o", data[i + j] & 0xFF));
                    if (j != lineLen - 1) sb.append(' ');
                }
                sb.append('\n');
            }
            return sb.toString();
        }

        public static String decimalGrid(byte[] data, int offset, int bytesPerLine) {
            StringBuilder sb = new StringBuilder();
            sb.append("Offset    Octets (base 10)\n");
            for (int i = 0; i < data.length; i += bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, data.length - i);
                sb.append(String.format("%08X  ", i + offset));
                for (int j = 0; j < lineLen; j++) {
                    sb.append(String.format("%3d", data[i + j] & 0xFF));
                    if (j != lineLen - 1) sb.append(' ');
                }
                sb.append('\n');
            }
            return sb.toString();
        }
    }

    /* =========================================================
     * =====================  FORMATTERS  ======================
     * ========================================================= */
    public static class Format {
        public static String csv(byte[] data, boolean header) {
            StringBuilder sb = new StringBuilder();
            if (header) sb.append("idx,hex,dec,oct,binary\n");
            for (int i = 0; i < data.length; i++) {
                int v = data[i] & 0xFF;
                sb.append(i).append(',')
                  .append(String.format("0x%02X", v)).append(',')
                  .append(v).append(',')
                  .append(String.format("0%03o", v)).append(',')
                  .append(toBinary8(v)).append('\n');
            }
            return sb.toString();
        }

        public static String tsv(byte[] data, boolean header) {
            StringBuilder sb = new StringBuilder();
            if (header) sb.append("idx\thex\tdec\toct\tbinary\n");
            for (int i = 0; i < data.length; i++) {
                int v = data[i] & 0xFF;
                sb.append(i).append('\t')
                  .append(String.format("0x%02X", v)).append('\t')
                  .append(v).append('\t')
                  .append(String.format("0%03o", v)).append('\t')
                  .append(toBinary8(v)).append('\n');
            }
            return sb.toString();
        }

        public static String markdownTable(byte[] data) {
            StringBuilder sb = new StringBuilder();
            sb.append("| Idx | Hex  | Dec | Oct  | Bits      |\n");
            sb.append("|----:|:----:|----:|:----:|:---------:|\n");
            for (int i = 0; i < data.length; i++) {
                int v = data[i] & 0xFF;
                sb.append(String.format(Locale.ROOT,
                        "| %3d | 0x%02X | %3d | %04o | %s |\n",
                        i, v, v, v, toBinary8(v)));
            }
            return sb.toString();
        }

        public static String htmlTable(byte[] data) {
            StringBuilder sb = new StringBuilder();
            sb.append("<table>\n<thead><tr><th>Idx</th><th>Hex</th><th>Dec</th><th>Oct</th><th>Bits</th></tr></thead>\n<tbody>\n");
            for (int i = 0; i < data.length; i++) {
                int v = data[i] & 0xFF;
                sb.append("<tr>")
                  .append("<td>").append(i).append("</td>")
                  .append("<td>").append(String.format("0x%02X", v)).append("</td>")
                  .append("<td>").append(v).append("</td>")
                  .append("<td>").append(String.format("%04o", v)).append("</td>")
                  .append("<td>").append(toBinary8(v)).append("</td>")
                  .append("</tr>\n");
            }
            sb.append("</tbody>\n</table>\n");
            return sb.toString();
        }

        public static String json(byte[] data) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            for (int i = 0; i < data.length; i++) {
                int v = data[i] & 0xFF;
                if (i > 0) sb.append(',');
                sb.append("{\"index\":").append(i)
                  .append(",\"hex\":\"").append(String.format("0x%02X", v)).append('"')
                  .append(",\"dec\":").append(v)
                  .append(",\"oct\":\"").append(String.format("0%03o", v)).append('"')
                  .append(",\"bin\":\"").append(toBinary8(v)).append("\"}");
            }
            sb.append("]");
            return sb.toString();
        }

        public static String yaml(byte[] data) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < data.length; i++) {
                int v = data[i] & 0xFF;
                sb.append("- index: ").append(i).append('\n')
                  .append("  hex: ").append(String.format("0x%02X", v)).append('\n')
                  .append("  dec: ").append(v).append('\n')
                  .append("  oct: ").append(String.format("0%03o", v)).append('\n')
                  .append("  bin: ").append(toBinary8(v)).append('\n');
            }
            return sb.toString();
        }

        private static String toBinary8(int v) {
            String s = Integer.toBinaryString(v & 0xFF);
            if (s.length() < 8) s = "00000000".substring(s.length()) + s;
            return s;
        }
    }

    /* =========================================================
     * =======================  ENCODING  ======================
     * ========================================================= */
    public static class Encoding {
        public static String base64(byte[] data) {
            return Base64.getEncoder().encodeToString(data);
        }

        // RFC 4648 Base32 (A-Z2-7), no padding by default, can be added if needed.
        private static final char[] B32_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        public static String base32(byte[] bytes) {
            StringBuilder out = new StringBuilder((bytes.length * 8 + 4) / 5);
            int i = 0, index = 0;
            int currByte, nextByte;
            while (i < bytes.length) {
                currByte = (bytes[i] >= 0) ? bytes[i] : (bytes[i] + 256);
                int digit;
                if (index > 3) {
                    if ((i + 1) < bytes.length) nextByte = (bytes[i + 1] >= 0) ? bytes[i + 1] : (bytes[i + 1] + 256);
                    else nextByte = 0;
                    digit = currByte & (0xFF >> index);
                    index = (index + 5) % 8;
                    digit <<= index;
                    digit |= nextByte >> (8 - index);
                    i++;
                } else {
                    digit = (currByte >> (8 - (index + 5))) & 0x1F;
                    index = (index + 5) % 8;
                    if (index == 0) i++;
                }
                out.append(B32_ALPH[digit]);
            }
            return out.toString();
        }
    }

    /* =========================================================
     * ===================  LANGUAGE LITERALS  =================
     * ========================================================= */
    public static class Lang {
        public static String cArray(byte[] data, String name) {
            StringBuilder sb = new StringBuilder();
            sb.append("#include <stdint.h>\n");
            sb.append("const uint8_t ").append(name).append("[").append(data.length).append("] = {");
            for (int i = 0; i < data.length; i++) {
                if (i % 16 == 0) sb.append("\n  ");
                sb.append(String.format("0x%02X", data[i] & 0xFF));
                if (i != data.length - 1) sb.append(", ");
            }
            sb.append("\n};\n");
            return sb.toString();
        }

        public static String javaByteArray(byte[] data, String name) {
            StringBuilder sb = new StringBuilder();
            sb.append("byte[] ").append(name).append(" = new byte[] {");
            for (int i = 0; i < data.length; i++) {
                if (i % 16 == 0) sb.append("\n  ");
                sb.append("(byte)0x").append(String.format("%02X", data[i] & 0xFF));
                if (i != data.length - 1) sb.append(", ");
            }
            sb.append("\n};\n");
            return sb.toString();
        }

        public static String pythonBytes(byte[] data, String name) {
            StringBuilder sb = new StringBuilder();
            sb.append(name).append(" = bytes([");
            for (int i = 0; i < data.length; i++) {
                if (i % 16 == 0) sb.append("\n  ");
                sb.append(data[i] & 0xFF);
                if (i != data.length - 1) sb.append(", ");
            }
            sb.append("\n])\n");
            return sb.toString();
        }

        public static String goByteSlice(byte[] data, String name) {
            StringBuilder sb = new StringBuilder();
            sb.append(name).append(" := []byte{");
            for (int i = 0; i < data.length; i++) {
                if (i % 16 == 0) sb.append("\n  ");
                sb.append(String.format("0x%02X", data[i] & 0xFF));
                if (i != data.length - 1) sb.append(", ");
            }
            sb.append("\n}\n");
            return sb.toString();
        }
    }

    /* =========================================================
     * =====================  BIT UTILITIES  ===================
     * ========================================================= */
    public static class Bits {
        /** Extract 'len' bits starting at bit 'from' (0=LSB) from an int */
        public static int getBits(int value, int from, int len) {
            if (len <= 0 || from < 0 || from + len > 32) throw new IllegalArgumentException("range out of bounds");
            int mask = (len == 32) ? -1 : ((1 << len) - 1);
            return (value >>> from) & mask;
        }

        /** Set 'len' bits starting at 'from' to 'bits' (low len bits taken) */
        public static int setBits(int base, int from, int len, int bits) {
            if (len <= 0 || from < 0 || from + len > 32) throw new IllegalArgumentException("range out of bounds");
            int mask = (len == 32) ? -1 : ((1 << len) - 1);
            int cleared = base & ~(mask << from);
            return cleared | ((bits & mask) << from);
        }

        /** Extract arbitrary bit range from a byte array (big-endian bit numbering across bytes). */
        public static long extractBits(byte[] data, int bitOffset, int bitLength) {
            if (bitLength <= 0 || bitLength > 64) throw new IllegalArgumentException("bitLength 1..64");
            if (bitOffset < 0) throw new IllegalArgumentException("bitOffset >= 0");
            int byteIndex = bitOffset / 8;
            int intra = bitOffset % 8;
            int needed = (intra + bitLength + 7) / 8;
            if (byteIndex + needed > data.length) throw new IllegalArgumentException("range exceeds data length");
            long acc = 0;
            for (int i = 0; i < needed; i++) {
                acc = (acc << 8) | (data[byteIndex + i] & 0xFFL);
            }
            int shiftRight = (needed * 8) - intra - bitLength;
            return (acc >>> shiftRight) & ((bitLength == 64) ? -1L : ((1L << bitLength) - 1L));
        }

        /** Insert 'bitLength' bits of 'value' into byte array at 'bitOffset' (big-endian across bytes). */
        public static void insertBits(byte[] data, int bitOffset, int bitLength, long value) {
            if (bitLength <= 0 || bitLength > 64) throw new IllegalArgumentException("bitLength 1..64");
            if (bitOffset < 0) throw new IllegalArgumentException("bitOffset >= 0");
            int byteIndex = bitOffset / 8;
            int intra = bitOffset % 8;
            int needed = (intra + bitLength + 7) / 8;
            if (byteIndex + needed > data.length) throw new IllegalArgumentException("range exceeds data length");
            long mask = (bitLength == 64) ? -1L : ((1L << bitLength) - 1L);
            long cur = 0;
            for (int i = 0; i < needed; i++) cur = (cur << 8) | (data[byteIndex + i] & 0xFFL);
            int shiftRight = (needed * 8) - intra - bitLength;
            long cleared = cur & ~(mask << shiftRight);
            long with = cleared | ((value & mask) << shiftRight);
            for (int i = needed - 1; i >= 0; i--) {
                data[byteIndex + i] = (byte) (with & 0xFF);
                with >>>= 8;
            }
        }
    }

    /* =========================================================
     * ===================  BYTE/ENDIAN HELPERS  ===============
     * ========================================================= */
    public static class Words {
        public static byte[] toBytes(short v, ByteOrder order) {
            ByteBuffer b = ByteBuffer.allocate(2).order(order);
            b.putShort(v); return b.array();
        }
        public static byte[] toBytes(int v, ByteOrder order) {
            ByteBuffer b = ByteBuffer.allocate(4).order(order);
            b.putInt(v); return b.array();
        }
        public static byte[] toBytes(long v, ByteOrder order) {
            ByteBuffer b = ByteBuffer.allocate(8).order(order);
            b.putLong(v); return b.array();
        }
        public static short toShort(byte[] a, int off, ByteOrder order) {
            ByteBuffer b = ByteBuffer.wrap(a, off, 2).order(order); return b.getShort();
        }
        public static int toInt(byte[] a, int off, ByteOrder order) {
            ByteBuffer b = ByteBuffer.wrap(a, off, 4).order(order); return b.getInt();
        }
        public static long toLong(byte[] a, int off, ByteOrder order) {
            ByteBuffer b = ByteBuffer.wrap(a, off, 8).order(order); return b.getLong();
        }
    }
}
