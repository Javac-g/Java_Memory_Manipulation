import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * BitsBytesUltraPlus (Matrix Edition)
 * -----------------------------------
 * Single-file, no external deps. Dual-mode:
 *  - CLI if args are provided
 *  - Interactive REPL if no args
 *
 * Features:
 *  - Hexdump (colorized Matrix green), Binary/Octal/Decimal grids
 *  - CSV/TSV/Markdown/HTML, JSON/YAML
 *  - Base64/Base32 encodings
 *  - Language literals (C/Java/Python/Go)
 *  - Bitfield extract/insert; endian helpers
 *  - Intel HEX (auto Extended Linear Address if >64KiB)
 *  - Motorola S-Record (auto S1/S2/S3 by address width)
 *  - Sniffers: PNG, ELF, PE, PCAP
 *  - PCAP packet indexer (timestamps, lengths, offsets)
 *  - Plugin API (example: hexstream)
 *
 * Defaults (Matrix profile):
 *   - Prompt:  Matrix>
 *   - Bytes-per-line (BPL): 32
 *   - Color: ON (ANSI); CLI toggle --no-color ; REPL: color off
 *
 * Build:
 *   javac BitsBytesUltraPlus.java
 *
 * CLI examples:
 *   java BitsBytesUltraPlus --str "Wake up, Neo." --dump --json --b64
 *   java BitsBytesUltraPlus --in firmware.bin --dump --ihex --srec --md --out out
 *   java BitsBytesUltraPlus --in capture.pcap --detect --pcap-index
 *
 * Shell:
 *   java BitsBytesUltraPlus
 *   Matrix> read file.bin
 *   Matrix> detect
 *   Matrix> dump
 *   Matrix> pcap-index
 *   Matrix> export ihex out.hex
 *   Matrix> export srec out.s19
 *   Matrix> getbits 12 5
 *   Matrix> color off
 *   Matrix> bpl 32
 *   Matrix> quit
 */
public class BitsBytesUltraPlus {

    /* ============================ MAIN ============================ */

    public static void main(String[] args) {
        try {
            if (args.length == 0) {
                new Shell().run();
                return;
            }
            CliOptions opt = CliOptions.parse(args);
            byte[] data = loadInput(opt);
            if (data == null) {
                System.err.println("No input. Use --in <file>, --str <text>, or --stdin.");
                System.exit(2);
            }
            Context ctx = new Context(data, opt.color);
            ctx.bytesPerLine = opt.bytesPerLine; // default 32 (Matrix)
            runSelectedOutputs(ctx, opt);
        } catch (IllegalArgumentException iae) {
            System.err.println(iae.getMessage());
            System.exit(2);
        } catch (IOException ioe) {
            System.err.println("I/O error: " + ioe.getMessage());
            System.exit(1);
        }
    }

    /* ======================== Context / IO ======================== */

    static class Context {
        byte[] data;
        boolean color;
        int bytesPerLine = 32;    // MATRIX DEFAULT

        Context(byte[] data, boolean color) {
            this.data = data;
            this.color = color;
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

    private static void runSelectedOutputs(Context ctx, CliOptions opt) throws IOException {
        // dumps/grids
        if (opt.dump) emit(opt, Dump.hexDump(ctx, 0, ctx.bytesPerLine, true), ".dump.txt");
        if (opt.binTable) emit(opt, Dump.binaryTable(ctx, 0, ctx.bytesPerLine), ".bintable.txt");
        if (opt.octGrid) emit(opt, Dump.octalGrid(ctx, 0, ctx.bytesPerLine), ".octgrid.txt");
        if (opt.decGrid) emit(opt, Dump.decimalGrid(ctx, 0, ctx.bytesPerLine), ".decgrid.txt");

        // structured
        if (opt.json) emit(opt, Format.json(ctx.data), ".json");
        if (opt.yaml) emit(opt, Format.yaml(ctx.data), ".yaml");
        if (opt.csv)  emit(opt, Format.csv(ctx.data, true), ".csv");
        if (opt.tsv)  emit(opt, Format.tsv(ctx.data, true), ".tsv");
        if (opt.md)   emit(opt, Format.markdownTable(ctx.data), ".md");
        if (opt.html) emit(opt, Format.htmlTable(ctx.data), ".html");

        // encodings
        if (opt.b64) emit(opt, Encoding.base64(ctx.data), ".b64.txt");
        if (opt.b32) emit(opt, Encoding.base32(ctx.data), ".b32.txt");

        // language literals
        if (opt.cArr)    emit(opt, Lang.cArray(ctx.data, "data"), ".c.txt");
        if (opt.javaArr) emit(opt, Lang.javaByteArray(ctx.data, "data"), ".java.txt");
        if (opt.pyBytes) emit(opt, Lang.pythonBytes(ctx.data, "data"), ".py.txt");
        if (opt.goSlice) emit(opt, Lang.goByteSlice(ctx.data, "data"), ".go.txt");

        // exporters
        if (opt.ihex) emit(opt, Exporters.intelHexExtended(ctx.data, 0), ".ihex");
        if (opt.srec) emit(opt, Exporters.motorolaAuto(ctx.data, 0), ".srec");

        // sniffers / indexers
        if (opt.detect) emit(opt, Sniff.detectAll(ctx.data), ".detect.txt");
        if (opt.pcapIndex) emit(opt, Sniff.pcapIndex(ctx.data), ".pcap.txt");

        // plugins requested?
        for (String k : opt.plugins) {
            UltraPlugin p = PLUGINS.get(k);
            if (p == null) throw new IllegalArgumentException("Unknown plugin: --" + k);
            emit(opt, p.render(ctx), "." + k + ".txt");
        }

        // default action
        if (opt.nothingChosen()) emit(opt, Dump.hexDump(ctx, 0, ctx.bytesPerLine, true), ".dump.txt");
    }

    private static void emit(CliOptions opt, String content, String defaultSuffix) throws IOException {
        if (opt.outPrefix == null) {
            System.out.println(content);
        } else {
            String base = (opt.inFile != null) ? opt.inFile : "stdin";
            String out = opt.outPrefix.isEmpty() ? base + defaultSuffix : opt.outPrefix + defaultSuffix;
            try (PrintWriter pw = new PrintWriter(out, "UTF-8")) { pw.print(content); }
            System.err.println("Wrote: " + out);
        }
    }

    /* =========================== CLI ============================ */

    static class CliOptions {
        String inFile = null;
        String literalString = null;
        boolean stdin = false;
        boolean color = true;

        boolean dump = false, binTable = false, octGrid = false, decGrid = false;
        boolean json = false, yaml = false, csv = false, tsv = false, md = false, html = false;
        boolean b64 = false, b32 = false;
        boolean cArr=false, javaArr=false, pyBytes=false, goSlice=false;
        boolean ihex=false, srec=false;
        boolean detect=false, pcapIndex=false;

        List<String> plugins = new ArrayList<>();

        String outPrefix = null;
        int bytesPerLine = 32;   // MATRIX DEFAULT

        static CliOptions parse(String[] args) {
            CliOptions o = new CliOptions();
            for (int i=0; i<args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "--in": o.inFile = need(args, ++i, "--in <file>"); break;
                    case "--str": o.literalString = need(args, ++i, "--str <text>"); break;
                    case "--stdin": o.stdin = true; break;
                    case "--no-color": o.color = false; break;

                    case "--dump": o.dump=true; break;
                    case "--bin":  o.binTable=true; break;
                    case "--oct":  o.octGrid=true; break;
                    case "--dec":  o.decGrid=true; break;

                    case "--json": o.json=true; break;
                    case "--yaml": o.yaml=true; break;
                    case "--csv":  o.csv=true; break;
                    case "--tsv":  o.tsv=true; break;
                    case "--md":   o.md=true; break;
                    case "--html": o.html=true; break;

                    case "--b64":  o.b64=true; break;
                    case "--b32":  o.b32=true; break;

                    case "--c":    o.cArr=true; break;
                    case "--java": o.javaArr=true; break;
                    case "--py":   o.pyBytes=true; break;
                    case "--go":   o.goSlice=true; break;

                    case "--ihex": o.ihex=true; break;
                    case "--srec": o.srec=true; break;

                    case "--detect": o.detect=true; break;
                    case "--pcap-index": o.pcapIndex=true; break;

                    case "--plugin":
                        o.plugins.add(need(args, ++i, "--plugin <name>")); break;

                    case "--out":  o.outPrefix = need(args, ++i, "--out <prefix-or-empty>"); break;
                    case "--bpl":  o.bytesPerLine = Integer.parseInt(need(args, ++i, "--bpl <int>")); break;

                    case "--help": case "-h": throw new IllegalArgumentException(usage());
                    default:
                        if (a.startsWith("--")) {
                            // allow --hexstream shorthand for plugins registered by key
                            String key = a.substring(2);
                            if (PLUGINS.containsKey(key)) { o.plugins.add(key); break; }
                        }
                        throw new IllegalArgumentException("Unknown arg: " + a + "\n\n" + usage());
                }
            }
            if ((o.inFile!=null?1:0) + (o.literalString!=null?1:0) + (o.stdin?1:0) > 1)
                throw new IllegalArgumentException("Use only one of --in, --str, or --stdin.");
            return o;
        }

        boolean nothingChosen() {
            return !(dump||binTable||octGrid||decGrid||json||yaml||csv||tsv||md||html||b64||b32||
                    cArr||javaArr||pyBytes||goSlice||ihex||srec||detect||pcapIndex||!plugins.isEmpty());
        }

        static String need(String[] args, int idx, String msg) {
            if (idx>=args.length) throw new IllegalArgumentException(msg);
            return args[idx];
        }

        static String usage() {
            return String.join("\n",
                "BitsBytesUltraPlus (Matrix) - single-file ultimate suite",
                "Usage:",
                "  java BitsBytesUltraPlus (--in <file> | --str <text> | --stdin) [formats] [--out <prefix>] [--bpl <n>] [--no-color]",
                "  java BitsBytesUltraPlus   (no args) -> interactive shell",
                "",
                "Formats:",
                "  --dump  --bin  --oct  --dec",
                "  --json  --yaml  --csv  --tsv  --md  --html",
                "  --b64   --b32",
                "  --c     --java  --py   --go",
                "  --ihex  --srec",
                "  --detect          (sniff PNG/ELF/PE/PCAP)",
                "  --pcap-index      (list PCAP packets: ts, incl-len, orig-len, file offsets)",
                "  --plugin <name>   (run registered plugin; e.g., hexstream)",
                "",
                "Options:",
                "  --bpl <n>         Bytes per line for dump/grids (default 32)",
                "  --out <prefix>    Write each output to a file using prefix (or empty to auto-name)",
                "  --no-color        Disable Matrix ANSI colors"
            );
        }
    }

    /* ========================= SHELL (REPL) ========================= */

    static class Shell {
        private final Scanner sc = new Scanner(System.in);
        private byte[] data = new byte[0];
        private boolean color = true;
        private int bpl = 32;                          // MATRIX DEFAULT
        private final String PROMPT = "Matrix> ";      // MATRIX PROMPT

        void run() {
            println("BitsBytesUltraPlus Shell (Matrix). Type 'help' for commands.");
            while (true) {
                System.out.print(PROMPT);
                if (!sc.hasNextLine()) break;
                String line = sc.nextLine().trim();
                if (line.isEmpty()) continue;
                try {
                    if (line.equalsIgnoreCase("quit") || line.equalsIgnoreCase("exit")) break;
                    if (line.equalsIgnoreCase("help")) { help(); continue; }
                    if (line.startsWith("read ")) { readCmd(line.substring(5).trim()); continue; }
                    if (line.equals("dump")) { System.out.print(Dump.hexDump(new Context(data,color),0,bpl,true)); continue; }
                    if (line.equals("bin"))  { System.out.print(Dump.binaryTable(new Context(data,color),0,bpl)); continue; }
                    if (line.equals("oct"))  { System.out.print(Dump.octalGrid(new Context(data,color),0,bpl)); continue; }
                    if (line.equals("dec"))  { System.out.print(Dump.decimalGrid(new Context(data,color),0,bpl)); continue; }

                    if (line.equals("json")) { System.out.println(Format.json(data)); continue; }
                    if (line.equals("yaml")) { System.out.println(Format.yaml(data)); continue; }
                    if (line.equals("csv"))  { System.out.println(Format.csv(data,true)); continue; }
                    if (line.equals("tsv"))  { System.out.println(Format.tsv(data,true)); continue; }
                    if (line.equals("md"))   { System.out.println(Format.markdownTable(data)); continue; }
                    if (line.equals("html")) { System.out.println(Format.htmlTable(data)); continue; }

                    if (line.equals("b64")) { System.out.println(Encoding.base64(data)); continue; }
                    if (line.equals("b32")) { System.out.println(Encoding.base32(data)); continue; }

                    if (line.equals("detect")) { System.out.print(Sniff.detectAll(data)); continue; }
                    if (line.equals("pcap-index")) { System.out.print(Sniff.pcapIndex(data)); continue; }

                    if (line.startsWith("export ")) { exportCmd(line.substring(7).trim()); continue; }
                    if (line.startsWith("getbits ")) { getbitsCmd(line.substring(8).trim()); continue; }
                    if (line.startsWith("setbits ")) { setbitsCmd(line.substring(8).trim()); continue; }

                    if (line.startsWith("bpl ")) { bpl = Integer.parseInt(line.split("\\s+")[1]); println("bpl="+bpl); continue; }
                    if (line.startsWith("color ")) { color = !line.toLowerCase(Locale.ROOT).contains("off"); println("color="+color); continue; }

                    if (line.startsWith("plugin ")) { pluginCmd(line.substring(7).trim()); continue; }

                    println("Unknown command. Type 'help'.");
                } catch (Exception e) {
                    println("Error: " + e.getMessage());
                }
            }
            println("Bye.");
        }

        void help() {
            println(String.join("\n",
                "Commands:",
                "  read <file>              Load bytes",
                "  dump | bin | oct | dec   Dumps/grids (Matrix green)",
                "  json | yaml | csv | tsv | md | html",
                "  b64  | b32",
                "  detect                   Sniff PNG/ELF/PE/PCAP",
                "  pcap-index               List PCAP packets (ts, incl-len, orig-len, offsets)",
                "  export ihex <file>       Write Intel HEX (auto extended)",
                "  export srec <file>       Write Motorola S-Records (S1/S2/S3 auto)",
                "  getbits <offset> <len>   Extract bit range (big-endian across bytes)",
                "  setbits <offset> <len> <value>   Insert bits (modifies buffer)",
                "  plugin <name>            Run a registered plugin (e.g., hexstream)",
                "  bpl <n>                  Set bytes per line",
                "  color on|off             Toggle ANSI Matrix color",
                "  quit"
            ));
        }

        void readCmd(String path) throws IOException {
            data = Files.readAllBytes(new File(path).toPath());
            println("Loaded " + data.length + " bytes from " + path);
        }

        void exportCmd(String rest) throws IOException {
            String[] t = rest.split("\\s+");
            if (t.length < 2) { println("Usage: export (ihex|srec) <file>"); return; }
            String fmt = t[0].toLowerCase(Locale.ROOT);
            String out = t[1];
            String content;
            if (fmt.equals("ihex")) content = Exporters.intelHexExtended(data, 0);
            else if (fmt.equals("srec")) content = Exporters.motorolaAuto(data, 0);
            else { println("Unknown exporter: " + fmt); return; }
            try (PrintWriter pw = new PrintWriter(out,"UTF-8")) { pw.print(content); }
            println("Wrote " + out);
        }

        void pluginCmd(String name) throws Exception {
            UltraPlugin p = PLUGINS.get(name);
            if (p == null) { println("No such plugin: " + name); return; }
            String out = p.render(new Context(data, color));
            System.out.println(out);
        }

        void getbitsCmd(String rest) {
            String[] t = rest.split("\\s+");
            if (t.length < 2) { println("Usage: getbits <bitOffset> <bitLen>"); return; }
            int off = Integer.parseInt(t[0]), len = Integer.parseInt(t[1]);
            long v = Bits.extractBits(data, off, len);
            println("0x"+Long.toHexString(v).toUpperCase(Locale.ROOT)+" ("+v+")");
        }

        void setbitsCmd(String rest) {
            String[] t = rest.split("\\s+");
            if (t.length < 3) { println("Usage: setbits <bitOffset> <bitLen> <value>"); return; }
            int off = Integer.parseInt(t[0]), len = Integer.parseInt(t[1]);
            long val = parseNumber(t[2]);
            Bits.insertBits(data, off, len, val);
            println("OK.");
        }

        long parseNumber(String s) {
            s = s.trim().toLowerCase(Locale.ROOT);
            if (s.startsWith("0x")) return Long.parseLong(s.substring(2), 16);
            if (s.startsWith("0b")) return Long.parseLong(s.substring(2), 2);
            return Long.parseLong(s, 10);
        }

        void println(String s){ System.out.println(s); }
    }

    /* ===================== Dumps (Matrix color) ===================== */

    static class Dump {
        private static final Pattern PRINTABLE = Pattern.compile("[\\x20-\\x7E]");
        // Matrix ANSI palette
        private static final String RESET = "\u001B[0m";
        private static final String DIM   = "\u001B[2m";
        private static final String GREEN = "\u001B[32m";
        private static final String BRIGHT_GREEN = "\u001B[92m";

        static String hexDump(Context ctx, int offset, int bytesPerLine, boolean showAscii) {
            StringBuilder sb = new StringBuilder();
            boolean color = ctx.color;
            byte[] data = ctx.data;
            int n = data.length;
            for (int i=0;i<n;i+=bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, n-i);
                // offset
                sb.append(color?DIM:"").append(String.format("%08X", i+offset)).append(color?RESET:"").append("  ");
                // hex octets (grouped per 2)
                for (int j=0;j<bytesPerLine;j++) {
                    if (j<lineLen) {
                        String oct = String.format("%02X", data[i+j] & 0xFF);
                        sb.append(color ? GREEN : "").append(oct).append(color?RESET:"");
                    } else {
                        sb.append("  ");
                    }
                    if (j%2==1) sb.append(' ');
                }
                if (showAscii) {
                    sb.append(" |");
                    for (int j=0;j<lineLen;j++) {
                        int v = data[i+j] & 0xFF;
                        char c = (v>=0x20 && v<=0x7E)?(char)v:'.';
                        String s = Character.toString(c);
                        sb.append(color?BRIGHT_GREEN:"").append(s).append(color?RESET:"");
                    }
                    sb.append('|');
                }
                sb.append('\n');
            }
            return sb.toString();
        }

        static String binaryTable(Context ctx, int offset, int bytesPerLine) {
            StringBuilder sb = new StringBuilder();
            boolean color = ctx.color;
            sb.append("Offset    ");
            for (int b=7;b>=0;b--) sb.append(' ').append(b);
            sb.append('\n');
            for (int i=0;i<ctx.data.length;i+=bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, ctx.data.length-i);
                for (int j=0;j<lineLen;j++) {
                    byte val = ctx.data[i+j];
                    sb.append(String.format("%08X  ", i+j+offset));
                    for (int bit=7;bit>=0;bit--) {
                        int bitv = (val>>bit)&1;
                        if (color) sb.append(bitv==1?BRIGHT_GREEN:GREEN);
                        sb.append(' ').append(bitv);
                        if (color) sb.append(RESET);
                    }
                    sb.append('\n');
                }
            }
            return sb.toString();
        }

        static String octalGrid(Context ctx, int offset, int bytesPerLine) {
            StringBuilder sb = new StringBuilder();
            boolean color = ctx.color;
            sb.append("Offset    Octets (base 8)\n");
            for (int i=0;i<ctx.data.length;i+=bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, ctx.data.length-i);
                sb.append(String.format("%08X  ", i+offset));
                for (int j=0;j<lineLen;j++) {
                    String o = String.format("%03o", ctx.data[i+j] & 0xFF);
                    sb.append(color?GREEN:"").append(o).append(color?RESET:"");
                    if (j!=lineLen-1) sb.append(' ');
                }
                sb.append('\n');
            }
            return sb.toString();
        }

        static String decimalGrid(Context ctx, int offset, int bytesPerLine) {
            StringBuilder sb = new StringBuilder();
            boolean color = ctx.color;
            sb.append("Offset    Octets (base 10)\n");
            for (int i=0;i<ctx.data.length;i+=bytesPerLine) {
                int lineLen = Math.min(bytesPerLine, ctx.data.length-i);
                sb.append(String.format("%08X  ", i+offset));
                for (int j=0;j<lineLen;j++) {
                    String d = String.format("%3d", ctx.data[i+j] & 0xFF);
                    sb.append(color?GREEN:"").append(d).append(color?RESET:"");
                    if (j!=lineLen-1) sb.append(' ');
                }
                sb.append('\n');
            }
            return sb.toString();
        }
    }

    /* ===================== Column & Structured ===================== */

    static class Format {
        static String csv(byte[] data, boolean header) {
            StringBuilder sb = new StringBuilder();
            if (header) sb.append("idx,hex,dec,oct,binary\n");
            for (int i=0;i<data.length;i++) {
                int v = data[i]&0xFF;
                sb.append(i).append(',')
                  .append(String.format("0x%02X", v)).append(',')
                  .append(v).append(',')
                  .append(String.format("0%03o", v)).append(',')
                  .append(toBinary8(v)).append('\n');
            }
            return sb.toString();
        }
        static String tsv(byte[] data, boolean header) {
            StringBuilder sb = new StringBuilder();
            if (header) sb.append("idx\thex\tdec\toct\tbinary\n");
            for (int i=0;i<data.length;i++) {
                int v = data[i]&0xFF;
                sb.append(i).append('\t')
                  .append(String.format("0x%02X", v)).append('\t')
                  .append(v).append('\t')
                  .append(String.format("0%03o", v)).append('\t')
                  .append(toBinary8(v)).append('\n');
            }
            return sb.toString();
        }
        static String markdownTable(byte[] data) {
            StringBuilder sb = new StringBuilder();
            sb.append("| Idx | Hex  | Dec | Oct  | Bits      |\n");
            sb.append("|----:|:----:|----:|:----:|:---------:|\n");
            for (int i=0;i<data.length;i++) {
                int v = data[i]&0xFF;
                sb.append(String.format(Locale.ROOT,
                    "| %3d | 0x%02X | %3d | %04o | %s |\n",
                    i, v, v, v, toBinary8(v)));
            }
            return sb.toString();
        }
        static String htmlTable(byte[] data) {
            StringBuilder sb = new StringBuilder();
            sb.append("<table>\n<thead><tr><th>Idx</th><th>Hex</th><th>Dec</th><th>Oct</th><th>Bits</th></tr></thead>\n<tbody>\n");
            for (int i=0;i<data.length;i++) {
                int v = data[i]&0xFF;
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
        static String json(byte[] data) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            for (int i=0;i<data.length;i++) {
                int v = data[i]&0xFF;
                if (i>0) sb.append(',');
                sb.append("{\"index\":").append(i)
                  .append(",\"hex\":\"").append(String.format("0x%02X", v)).append('"')
                  .append(",\"dec\":").append(v)
                  .append(",\"oct\":\"").append(String.format("0%03o", v)).append('"')
                  .append(",\"bin\":\"").append(toBinary8(v)).append("\"}");
            }
            sb.append("]");
            return sb.toString();
        }
        static String yaml(byte[] data) {
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<data.length;i++) {
                int v = data[i]&0xFF;
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
            if (s.length()<8) s = "00000000".substring(s.length())+s;
            return s;
        }
    }

    /* ============================ Encoding ============================ */

    static class Encoding {
        static String base64(byte[] data) { return Base64.getEncoder().encodeToString(data); }

        private static final char[] B32_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        static String base32(byte[] bytes) {
            StringBuilder out = new StringBuilder((bytes.length*8+4)/5);
            int i=0, index=0, curr, next;
            while (i<bytes.length) {
                curr = (bytes[i]>=0)?bytes[i]:bytes[i]+256;
                int digit;
                if (index>3) {
                    next = (i+1<bytes.length)?((bytes[i+1]>=0)?bytes[i+1]:bytes[i+1]+256):0;
                    digit = curr & (0xFF>>index);
                    index=(index+5)%8;
                    digit <<= index;
                    digit |= next>>(8-index);
                    i++;
                } else {
                    digit = (curr>>(8-(index+5))) & 0x1F;
                    index=(index+5)%8;
                    if (index==0) i++;
                }
                out.append(B32_ALPH[digit]);
            }
            return out.toString();
        }
    }

    /* ======================== Language Literals ======================== */

    static class Lang {
        static String cArray(byte[] data, String name) {
            StringBuilder sb=new StringBuilder();
            sb.append("#include <stdint.h>\n");
            sb.append("const uint8_t ").append(name).append("[").append(data.length).append("] = {");
            for (int i=0;i<data.length;i++){ if(i%32==0) sb.append("\n  "); sb.append(String.format("0x%02X", data[i]&0xFF)); if(i!=data.length-1) sb.append(", "); }
            sb.append("\n};\n"); return sb.toString();
        }
        static String javaByteArray(byte[] data, String name) {
            StringBuilder sb=new StringBuilder();
            sb.append("byte[] ").append(name).append(" = new byte[] {");
            for (int i=0;i<data.length;i++){ if(i%32==0) sb.append("\n  "); sb.append("(byte)0x").append(String.format("%02X", data[i]&0xFF)); if(i!=data.length-1) sb.append(", "); }
            sb.append("\n};\n"); return sb.toString();
        }
        static String pythonBytes(byte[] data, String name) {
            StringBuilder sb=new StringBuilder();
            sb.append(name).append(" = bytes([");
            for (int i=0;i<data.length;i++){ if(i%32==0) sb.append("\n  "); sb.append(data[i]&0xFF); if(i!=data.length-1) sb.append(", "); }
            sb.append("\n])\n"); return sb.toString();
        }
        static String goByteSlice(byte[] data, String name) {
            StringBuilder sb=new StringBuilder();
            sb.append(name).append(" := []byte{");
            for (int i=0;i<data.length;i++){ if(i%32==0) sb.append("\n  "); sb.append(String.format("0x%02X", data[i]&0xFF)); if(i!=data.length-1) sb.append(", "); }
            sb.append("\n}\n"); return sb.toString();
        }
    }

    /* ============================ Bits / Words ============================ */

    static class Bits {
        static int getBits(int value, int from, int len) {
            if(len<=0||from<0||from+len>32) throw new IllegalArgumentException("range out of bounds");
            int mask = (len==32)?-1:((1<<len)-1);
            return (value>>>from) & mask;
        }
        static int setBits(int base, int from, int len, int bits) {
            if(len<=0||from<0||from+len>32) throw new IllegalArgumentException("range out of bounds");
            int mask = (len==32)?-1:((1<<len)-1);
            int cleared = base & ~(mask<<from);
            return cleared | ((bits & mask)<<from);
        }
        static long extractBits(byte[] data, int bitOffset, int bitLength) {
            if(bitLength<=0||bitLength>64) throw new IllegalArgumentException("bitLength 1..64");
            if(bitOffset<0) throw new IllegalArgumentException("bitOffset >= 0");
            int byteIndex = bitOffset/8;
            int intra = bitOffset%8;
            int needed = (intra+bitLength+7)/8;
            if (byteIndex+needed>data.length) throw new IllegalArgumentException("range exceeds data length");
            long acc=0;
            for(int i=0;i<needed;i++) acc=(acc<<8)|(data[byteIndex+i]&0xFFL);
            int shiftRight = (needed*8)-intra-bitLength;
            return (acc>>>shiftRight) & ((bitLength==64)?-1L:((1L<<bitLength)-1L));
        }
        static void insertBits(byte[] data, int bitOffset, int bitLength, long value) {
            if(bitLength<=0||bitLength>64) throw new IllegalArgumentException("bitLength 1..64");
            if(bitOffset<0) throw new IllegalArgumentException("bitOffset >= 0");
            int byteIndex = bitOffset/8;
            int intra = bitOffset%8;
            int needed = (intra+bitLength+7)/8;
            if (byteIndex+needed>data.length) throw new IllegalArgumentException("range exceeds data length");
            long mask = (bitLength==64)?-1L:((1L<<bitLength)-1L);
            long cur=0;
            for(int i=0;i<needed;i++) cur=(cur<<8)|(data[byteIndex+i]&0xFFL);
            int shiftRight = (needed*8)-intra-bitLength;
            long cleared = cur & ~(mask<<shiftRight);
            long with = cleared | ((value & mask)<<shiftRight);
            for(int i=needed-1;i>=0;i--){ data[byteIndex+i]=(byte)(with&0xFF); with>>>=8; }
        }
    }

    static class Words {
        static byte[] toBytes(short v, ByteOrder o){ ByteBuffer b=ByteBuffer.allocate(2).order(o); b.putShort(v); return b.array(); }
        static byte[] toBytes(int v, ByteOrder o){ ByteBuffer b=ByteBuffer.allocate(4).order(o); b.putInt(v); return b.array(); }
        static byte[] toBytes(long v, ByteOrder o){ ByteBuffer b=ByteBuffer.allocate(8).order(o); b.putLong(v); return b.array(); }
        static short toShort(byte[] a,int off,ByteOrder o){ return ByteBuffer.wrap(a,off,2).order(o).getShort(); }
        static int toInt(byte[] a,int off,ByteOrder o){ return ByteBuffer.wrap(a,off,4).order(o).getInt(); }
        static long toLong(byte[] a,int off,ByteOrder o){ return ByteBuffer.wrap(a,off,8).order(o).getLong(); }
    }

    /* ============================ Exporters ============================ */

    static class Exporters {
        /**
         * Intel HEX with Extended Linear Address (ELAR) when address >= 0x10000.
         * We assume a linear address starting at baseAddress and advancing per-byte.
         */
        static String intelHexExtended(byte[] data, int baseAddress) {
            int recLen = 16;
            StringBuilder sb = new StringBuilder();
            int addr = baseAddress & 0xFFFF;
            int lastHigh = -1;

            for (int i = 0; i < data.length; i += recLen) {
                int len = Math.min(recLen, data.length - i);
                int absolute = baseAddress + i;
                int high = (absolute >>> 16) & 0xFFFF;
                int low = absolute & 0xFFFF;

                if (high != lastHigh) {
                    // Extended Linear Address record (type 04)
                    int csum = 2 + 0 + 4 + ((high >> 8) & 0xFF) + (high & 0xFF);
                    csum = ((~csum + 1) & 0xFF);
                    sb.append(':').append(String.format("%02X%04X%02X%04X%02X", 2, 0, 4, high, csum)).append('\n');
                    lastHigh = high;
                }

                int checksum = len + ((low >> 8) & 0xFF) + (low & 0xFF);
                sb.append(':').append(String.format("%02X%04X%02X", len, low, 0));
                for (int j = 0; j < len; j++) {
                    int b = data[i + j] & 0xFF;
                    checksum = (checksum + b) & 0xFF;
                    sb.append(String.format("%02X", b));
                }
                checksum = ((~checksum + 1) & 0xFF);
                sb.append(String.format("%02X", checksum)).append('\n');
            }
            // EOF record
            sb.append(":00000001FF\n");
            return sb.toString();
        }

        /**
         * Motorola S-Records auto: choose S1/S2/S3 based on address width needed.
         * We assume linear addresses starting at baseAddress.
         */
        static String motorolaAuto(byte[] data, int baseAddress) {
            int recLen = 16;
            StringBuilder sb = new StringBuilder();
            int maxAddr = baseAddress + Math.max(0, data.length - 1);

            int type;      // 1 -> S1 (16-bit), 2 -> S2 (24-bit), 3 -> S3 (32-bit)
            int addrBytes;
            if (maxAddr <= 0xFFFF) { type = 1; addrBytes = 2; }
            else if (maxAddr <= 0xFFFFFF) { type = 2; addrBytes = 3; }
            else { type = 3; addrBytes = 4; }

            for (int i = 0; i < data.length; i += recLen) {
                int len = Math.min(recLen, data.length - i);
                int addr = baseAddress + i;

                int byteCount = len + addrBytes + 1; // data + addr + checksum
                int sum = byteCount;
                sb.append('S').append(type);
                sb.append(String.format("%02X", byteCount));

                // address
                for (int ab = addrBytes - 1; ab >= 0; ab--) {
                    int val = (addr >> (ab * 8)) & 0xFF;
                    sb.append(String.format("%02X", val));
                    sum = (sum + val) & 0xFF;
                }

                for (int j = 0; j < len; j++) {
                    int b = data[i + j] & 0xFF;
                    sum = (sum + b) & 0xFF;
                    sb.append(String.format("%02X", b));
                }

                int cks = (~sum) & 0xFF;
                sb.append(String.format("%02X", cks)).append('\n');
            }

            // Termination record: S9 (S1), S8 (S2), S7 (S3)
            switch (type) {
                case 1: sb.append("S9030000FC\n"); break;
                case 2: sb.append("S804000000FB\n"); break; // minimal termination
                case 3: sb.append("S70500000000FA\n"); break;
            }
            return sb.toString();
        }
    }

    /* ============================ Sniffers / PCAP Index ============================ */

    static class Sniff {
        static String detectAll(byte[] buf) {
            StringBuilder sb = new StringBuilder();
            sb.append("== Sniff Results ==\n");
            boolean any = false;
            String s;
            s = png(buf); if (!s.isEmpty()) { sb.append(s); any = true; }
            s = elf(buf); if (!s.isEmpty()) { sb.append(s); any = true; }
            s = pe(buf);  if (!s.isEmpty()) { sb.append(s); any = true; }
            s = pcap(buf);if (!s.isEmpty()) { sb.append(s); any = true; }
            if (!any) sb.append("No known headers recognized.\n");
            return sb.toString();
        }

        static String png(byte[] b) {
            if (b.length<24) return "";
            byte[] sig = new byte[]{(byte)137,80,78,71,13,10,26,10};
            for(int i=0;i<8;i++) if (b[i]!=sig[i]) return "";
            if (b.length<33) return "PNG: signature OK, too short to read IHDR\n";
            int w = (int)((b[16]&0xFFL)<<24 | (b[17]&0xFFL)<<16 | (b[18]&0xFFL)<<8 | (b[19]&0xFFL));
            int h = (int)((b[20]&0xFFL)<<24 | (b[21]&0xFFL)<<16 | (b[22]&0xFFL)<<8 | (b[23]&0xFFL));
            int bitDepth = b[24]&0xFF;
            int colorType = b[25]&0xFF;
            return String.format("PNG: %dx%d, bitDepth=%d, colorType=%d\n", w,h,bitDepth,colorType);
        }

        static String elf(byte[] b) {
            if (b.length<52) return "";
            if (b[0]!=0x7F || b[1]!='E' || b[2]!='L' || b[3]!='F') return "";
            int cls = b[4]&0xFF; // 1=32,2=64
            int endian = b[5]&0xFF; // 1=little,2=big
            int type = ((b[16]&0xFF) | ((b[17]&0xFF)<<8));
            int machine = ((b[18]&0xFF) | ((b[19]&0xFF)<<8));
            return String.format("ELF: class=%s, endian=%s, type=0x%04X, machine=0x%04X\n",
                    (cls==1?"32-bit":cls==2?"64-bit":"?"),
                    (endian==1?"little":endian==2?"big":"?"),
                    type, machine);
        }

        static String pe(byte[] b) {
            if (b.length<0x40) return "";
            if (b[0]!='M' || b[1]!='Z') return "";
            int peOff = ((b[0x3C]&0xFF) | ((b[0x3D]&0xFF)<<8) | ((b[0x3E]&0xFF)<<16) | ((b[0x3F]&0xFF)<<24));
            if (peOff+6>=b.length) return "PE: MZ found, PE header beyond file size\n";
            if (!(b[peOff]=='P' && b[peOff+1]=='E' && b[peOff+2]==0 && b[peOff+3]==0)) return "PE: MZ found, PE signature missing\n";
            int machine = ((b[peOff+4]&0xFF) | ((b[peOff+5]&0xFF)<<8));
            int sections = ((b[peOff+6]&0xFF) | ((b[peOff+7]&0xFF)<<8));
            return String.format("PE: machine=0x%04X, sections=%d\n", machine, sections);
        }

        static String pcap(byte[] b) {
            if (b.length<24) return "";
            int magic = (b[0]&0xFF) | ((b[1]&0xFF)<<8) | ((b[2]&0xFF)<<16) | ((b[3]&0xFF)<<24);
            boolean le = (magic==0xA1B2C3D4 || magic==0xA1B23C4D);
            boolean be = (magic==0xD4C3B2A1 || magic==0x4D3CB2A1);
            if (!le && !be) return "";
            ByteOrder o = le?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN;
            int versionMajor = getU16(b,4,o);
            int versionMinor = getU16(b,6,o);
            int snaplen = getU32(b,16,o);
            int network = getU32(b,20,o);
            return String.format("PCAP: endian=%s, v=%d.%d, snaplen=%d, linktype=%d\n",
                    le?"LE":"BE", versionMajor, versionMinor, snaplen, network);
        }

        static String pcapIndex(byte[] b) {
            if (b.length<24) return "PCAP Index: Not a pcap or too short.\n";
            int magic = (b[0]&0xFF) | ((b[1]&0xFF)<<8) | ((b[2]&0xFF)<<16) | ((b[3]&0xFF)<<24);
            boolean le = (magic==0xA1B2C3D4 || magic==0xA1B23C4D);
            boolean be = (magic==0xD4C3B2A1 || magic==0x4D3CB2A1);
            if (!le && !be) return "PCAP Index: Not a recognized pcap magic.\n";
            ByteOrder o = le?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN;

            int offset = 24;
            StringBuilder sb = new StringBuilder();
            sb.append("== PCAP Packet Index ==\n");
            sb.append(String.format("Endian=%s\n", le?"LE":"BE"));
            sb.append("Idx | FileOff |    TS (epoch)          | InclLen | OrigLen\n");
            sb.append("----+---------+------------------------+---------+--------\n");
            int idx = 0;
            while (offset + 16 <= b.length) {
                long ts_sec  = getU32L(b, offset, o);      // 4
                long ts_usec = getU32L(b, offset+4, o);    // 4
                long incl    = getU32L(b, offset+8, o);    // 4
                long orig    = getU32L(b, offset+12, o);   // 4
                long fileOff = offset;
                long epochNs = ts_sec*1_000_000_000L + ts_usec*1000L;
                sb.append(String.format(Locale.ROOT, "%3d | %7d | %s | %7d | %7d\n",
                        idx, fileOff, Instant.ofEpochMilli(epochNs/1_000_000L), incl, orig));
                offset += 16;
                if (offset + incl > b.length) { sb.append("(truncated)\n"); break; }
                offset += (int)incl;
                idx++;
            }
            return sb.toString();
        }

        static int getU16(byte[] b, int off, ByteOrder o){
            return o==ByteOrder.LITTLE_ENDIAN
                    ? ((b[off]&0xFF)|((b[off+1]&0xFF)<<8))
                    : (((b[off]&0xFF)<<8)|(b[off+1]&0xFF));
        }
        static int getU32(byte[] b, int off, ByteOrder o){
            return o==ByteOrder.LITTLE_ENDIAN
                    ? (b[off]&0xFF)|((b[off+1]&0xFF)<<8)|((b[off+2]&0xFF)<<16)|((b[off+3]&0xFF)<<24)
                    : ((b[off]&0xFF)<<24)|((b[off+1]&0xFF)<<16)|((b[off+2]&0xFF)<<8)|(b[off+3]&0xFF);
        }
        static long getU32L(byte[] b, int off, ByteOrder o){ return getU32(b, off, o) & 0xFFFFFFFFL; }
    }

    /* ============================ Plugin API ============================ */

    interface UltraPlugin {
        String key();                 // used as --<key> or "plugin <key>"
        String description();
        String render(Context ctx) throws Exception;
    }

    static final Map<String, UltraPlugin> PLUGINS = new LinkedHashMap<>();
    static {
        // Example plugin: continuous lowercase hex stream
        PLUGINS.put("hexstream", new UltraPlugin() {
            public String key(){ return "hexstream"; }
            public String description(){ return "Continuous hex nibbles (no spaces), lowercase"; }
            public String render(Context ctx) {
                StringBuilder sb=new StringBuilder(ctx.data.length*2);
                for (byte b: ctx.data) sb.append(String.format("%02x", b&0xFF));
                return sb.toString();
            }
        });
    }
}
