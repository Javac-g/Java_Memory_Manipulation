import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;

/**
 * BitsBytesUltra - one-file ultra suite for bit/byte manipulation, dumps, exports, sniffers, and REPL.
 *
 * Dual mode:
 *  - With args -> CLI
 *  - Without args -> interactive shell
 *
 * Color is ON by default (ANSI). Disable with --no-color or "color off" in REPL.
 *
 * Build:
 *   javac BitsBytesUltra.java
 * Run examples:
 *   java BitsBytesUltra --str "Feel the power." --dump --json --b64
 *   java BitsBytesUltra --in firmware.bin --dump --ihex --srec --md --out out
 *   java BitsBytesUltra         # (interactive shell)
 */
public class BitsBytesUltra {

    /* ============================ MAIN ============================ */

    public static void main(String[] args) {
        try {
            if (args.length == 0) {
                // Interactive shell
                new Shell().run();
                return;
            }
            CliOptions opt = CliOptions.parse(args);
            byte[] data = loadInput(opt);
            if (data == null) {
                System.err.println("No input. Use --in <file>, --str <text>, or pipe with --stdin.");
                System.exit(2);
            }
            Context ctx = new Context(data, opt.color);
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
        int bytesPerLine = 16;

        Context(byte[] data, boolean color) { this.data = data; this.color = color; }
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
        ctx.bytesPerLine = opt.bytesPerLine;

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
        if (opt.ihex) emit(opt, Exporters.intelHex(ctx.data), ".ihex");
        if (opt.srec) emit(opt, Exporters.motorolaS19(ctx.data), ".srec");

        // sniffers
        if (opt.detect) emit(opt, Sniff.detectAll(ctx.data), ".detect.txt");

        // default action: dump
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
        boolean json=false,yaml=false,csv=false,tsv=false,md=false,html=false;
        boolean b64=false,b32=false;
        boolean cArr=false,javaArr=false,pyBytes=false,goSlice=false;
        boolean ihex=false,srec=false;
        boolean detect=false;

        String outPrefix = null;
        int bytesPerLine = 16;

        static CliOptions parse(String[] args) {
            CliOptions o = new CliOptions();
            if (args.length == 0) throw new IllegalArgumentException(usage());
            for (int i=0;i<args.length;i++) {
                String a = args[i];
                switch (a) {
                    case "--in": o.inFile = need(args, ++i, "--in <file>"); break;
                    case "--str": o.literalString = need(args, ++i, "--str <text>"); break;
                    case "--stdin": o.stdin = true; break;
                    case "--no-color": o.color = false; break;

                    case "--dump": o.dump=true; break;
                    case "--bin": o.binTable=true; break;
                    case "--oct": o.octGrid=true; break;
                    case "--dec": o.decGrid=true; break;

                    case "--json": o.json=true; break;
                    case "--yaml": o.yaml=true; break;
                    case "--csv": o.csv=true; break;
                    case "--tsv": o.tsv=true; break;
                    case "--md": o.md=true; break;
                    case "--html": o.html=true; break;

                    case "--b64": o.b64=true; break;
                    case "--b32": o.b32=true; break;

                    case "--c": o.cArr=true; break;
                    case "--java": o.javaArr=true; break;
                    case "--py": o.pyBytes=true; break;
                    case "--go": o.goSlice=true; break;

                    case "--ihex": o.ihex=true; break;
                    case "--srec": o.srec=true; break;

                    case "--detect": o.detect=true; break;

                    case "--out": o.outPrefix = need(args, ++i, "--out <prefix-or-empty>"); break;
                    case "--bpl": o.bytesPerLine = Integer.parseInt(need(args, ++i, "--bpl <int>")); break;

                    case "--help": case "-h": throw new IllegalArgumentException(usage());
                    default: throw new IllegalArgumentException("Unknown arg: "+a+"\n\n"+usage());
                }
            }
            if ((o.inFile!=null?1:0) + (o.literalString!=null?1:0) + (o.stdin?1:0) > 1)
                throw new IllegalArgumentException("Use only one of --in, --str, --stdin.");
            return o;
        }

        boolean nothingChosen() {
            return !(dump||binTable||octGrid||decGrid||json||yaml||csv||tsv||md||html||b64||b32||cArr||javaArr||pyBytes||goSlice||ihex||srec||detect);
        }

        static String need(String[] args, int idx, String msg) {
            if (idx>=args.length) throw new IllegalArgumentException(msg);
            return args[idx];
        }

        static String usage() {
            return String.join("\n",
                "BitsBytesUltra - ultimate byte/bit suite",
                "Usage:",
                "  java BitsBytesUltra (--in <file> | --str <text> | --stdin) [formats] [--out <prefix>] [--bpl <n>] [--no-color]",
                "  java BitsBytesUltra   (no args) -> interactive shell",
                "",
                "Formats:",
                "  --dump  --bin  --oct  --dec",
                "  --json  --yaml  --csv  --tsv  --md  --html",
                "  --b64   --b32",
                "  --c     --java  --py   --go",
                "  --ihex  --srec",
                "  --detect   (print best-effort header sniff results: PCAP/ELF/PE/PNG)",
                "",
                "Options:",
                "  --bpl <n>        Bytes per line (default 16)",
                "  --out <prefix>   Write each output to file using this prefix (or empty for auto)",
                "  --no-color       Disable ANSI colors for dump/grid outputs"
            );
        }
    }

    /* ========================= SHELL (REPL) ========================= */

    static class Shell {
        private final Scanner sc = new Scanner(System.in);
        private byte[] data = new byte[0];
        private boolean color = true;
        private int bpl = 16;

        void run() {
            println("BitsBytesUltra Shell. Type 'help' for commands.");
            while (true) {
                System.out.print("BitsBytes> ");
                if (!sc.hasNextLine()) break;
                String line = sc.nextLine().trim();
                if (line.isEmpty()) continue;
                try {
                    if (line.equalsIgnoreCase("quit") || line.equalsIgnoreCase("exit")) break;
                    if (line.equalsIgnoreCase("help")) { help(); continue; }
                    if (line.startsWith("read ")) { readCmd(line.substring(5).trim()); continue; }
                    if (line.equals("dump")) { System.out.print(Dump.hexDump(new Context(data,color),0,bpl,true)); continue; }
                    if (line.equals("bin")) { System.out.print(Dump.binaryTable(new Context(data,color),0,bpl)); continue; }
                    if (line.equals("oct")) { System.out.print(Dump.octalGrid(new Context(data,color),0,bpl)); continue; }
                    if (line.equals("dec")) { System.out.print(Dump.decimalGrid(new Context(data,color),0,bpl)); continue; }
                    if (line.equals("json")) { System.out.println(Format.json(data)); continue; }
                    if (line.equals("yaml")) { System.out.println(Format.yaml(data)); continue; }
                    if (line.equals("csv")) { System.out.println(Format.csv(data,true)); continue; }
                    if (line.equals("tsv")) { System.out.println(Format.tsv(data,true)); continue; }
                    if (line.equals("md")) { System.out.println(Format.markdownTable(data)); continue; }
                    if (line.equals("html")) { System.out.println(Format.htmlTable(data)); continue; }
                    if (line.equals("b64")) { System.out.println(Encoding.base64(data)); continue; }
                    if (line.equals("b32")) { System.out.println(Encoding.base32(data)); continue; }
                    if (line.startsWith("bpl ")) { bpl = Integer.parseInt(line.split("\\s+")[1]); println("bpl="+bpl); continue; }
                    if (line.startsWith("color ")) { color = !line.toLowerCase(Locale.ROOT).contains("off"); println("color="+color); continue; }
                    if (line.equals("detect")) { System.out.print(Sniff.detectAll(data)); continue; }
                    if (line.startsWith("export ")) { exportCmd(line.substring(7).trim()); continue; }
                    if (line.startsWith("getbits ")) { getbitsCmd(line.substring(8).trim()); continue; }
                    if (line.startsWith("setbits ")) { setbitsCmd(line.substring(8).trim()); continue; }
                    println("Unknown command. Type 'help'.");
                } catch (Exception e) {
                    println("Error: "+e.getMessage());
                }
            }
            println("Bye.");
        }

        void help() {
            println(String.join("\n",
                "Commands:",
                "  read <file>          Load bytes",
                "  dump | bin | oct | dec",
                "  json | yaml | csv | tsv | md | html",
                "  b64  | b32",
                "  detect               Sniff PCAP/ELF/PE/PNG",
                "  export ihex <file>   Write Intel HEX",
                "  export srec <file>   Write Motorola S-Record",
                "  getbits <offset> <len>      Extract bit range from current data (big-endian across bytes)",
                "  setbits <offset> <len> <val> Insert bits (modifies buffer)",
                "  bpl <n>              Set bytes per line",
                "  color on|off         Toggle ANSI color in dumps",
                "  quit"
            ));
        }

        void readCmd(String path) throws IOException {
            data = Files.readAllBytes(new File(path).toPath());
            println("Loaded "+data.length+" bytes from "+path);
        }

        void exportCmd(String rest) throws IOException {
            String[] t = rest.split("\\s+");
            if (t.length < 2) { println("Usage: export (ihex|srec) <file>"); return; }
            String fmt = t[0].toLowerCase(Locale.ROOT);
            String out = t[1];
            String content;
            if (fmt.equals("ihex")) content = Exporters.intelHex(data);
            else if (fmt.equals("srec")) content = Exporters.motorolaS19(data);
            else { println("Unknown exporter: "+fmt); return; }
            try (PrintWriter pw = new PrintWriter(out,"UTF-8")) { pw.print(content); }
            println("Wrote "+out);
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

    /* ===================== Dumps (with color) ===================== */

    static class Dump {
        private static final Pattern PRINTABLE = Pattern.compile("[\\x20-\\x7E]");
        // ANSI colors
        private static final String RESET = "\u001B[0m";
        private static final String DIM   = "\u001B[2m";
        private static final String CYAN  = "\u001B[36m";
        private static final String YELL  = "\u001B[33m";
        private static final String MAG   = "\u001B[35m";

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
                        sb.append(color ? (j%2==1?CYAN:YELL) : "").append(oct).append(color?RESET:"");
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
                        sb.append(color?MAG:"").append(s).append(color?RESET:"");
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
                        if (color) sb.append(bitv==1?CYAN:YELL);
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
                    sb.append(color?CYAN:"").append(o).append(color?RESET:"");
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
                    sb.append(color?CYAN:"").append(d).append(color?RESET:"");
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
        static String base64(byte[] data) {
            return Base64.getEncoder().encodeToString(data);
        }
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
            for (int i=0;i<data.length;i++){ if(i%16==0) sb.append("\n  "); sb.append(String.format("0x%02X", data[i]&0xFF)); if(i!=data.length-1) sb.append(", "); }
            sb.append("\n};\n"); return sb.toString();
        }
        static String javaByteArray(byte[] data, String name) {
            StringBuilder sb=new StringBuilder();
            sb.append("byte[] ").append(name).append(" = new byte[] {");
            for (int i=0;i<data.length;i++){ if(i%16==0) sb.append("\n  "); sb.append("(byte)0x").append(String.format("%02X", data[i]&0xFF)); if(i!=data.length-1) sb.append(", "); }
            sb.append("\n};\n"); return sb.toString();
        }
        static String pythonBytes(byte[] data, String name) {
            StringBuilder sb=new StringBuilder();
            sb.append(name).append(" = bytes([");
            for (int i=0;i<data.length;i++){ if(i%16==0) sb.append("\n  "); sb.append(data[i]&0xFF); if(i!=data.length-1) sb.append(", "); }
            sb.append("\n])\n"); return sb.toString();
        }
        static String goByteSlice(byte[] data, String name) {
            StringBuilder sb=new StringBuilder();
            sb.append(name).append(" := []byte{");
            for (int i=0;i<data.length;i++){ if(i%16==0) sb.append("\n  "); sb.append(String.format("0x%02X", data[i]&0xFF)); if(i!=data.length-1) sb.append(", "); }
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
        // Intel HEX: records of data with 16 bytes per line by default
        static String intelHex(byte[] data) {
            int recLen = 16;
            StringBuilder sb = new StringBuilder();
            int addr=0;
            for (int i=0;i<data.length;i+=recLen){
                int len = Math.min(recLen, data.length-i);
                sb.append(':');
                int checksum = len + ((addr>>8)&0xFF) + (addr&0xFF) + 0x00; // type 00
                sb.append(String.format("%02X%04X%02X", len, addr, 0));
                for (int j=0;j<len;j++){ int b=data[i+j]&0xFF; checksum=(checksum+b)&0xFF; sb.append(String.format("%02X", b)); }
                checksum = ((~checksum + 1) & 0xFF);
                sb.append(String.format("%02X", checksum)).append('\n');
                addr+=len;
            }
            // EOF record
            sb.append(":00000001FF\n");
            return sb.toString();
        }

        // Motorola S-Record S19 (S1 data records), 16 bytes per line
        static String motorolaS19(byte[] data) {
            int recLen = 16;
            StringBuilder sb = new StringBuilder();
            int addr=0;
            for (int i=0;i<data.length;i+=recLen){
                int len = Math.min(recLen, data.length-i);
                int byteCount = len + 3; // address(2 bytes) + data + checksum
                int sum = byteCount + ((addr>>8)&0xFF) + (addr&0xFF);
                sb.append('S').append('1').append(String.format("%02X", byteCount));
                sb.append(String.format("%04X", addr));
                for (int j=0;j<len;j++){ int b=data[i+j]&0xFF; sum=(sum+b)&0xFF; sb.append(String.format("%02X", b)); }
                int cks = (~sum) & 0xFF;
                sb.append(String.format("%02X", cks)).append('\n');
                addr+=len;
            }
            // S9 termination with address 0000
            sb.append("S9030000FC\n");
            return sb.toString();
        }
    }

    /* ============================ Sniffers ============================ */

    static class Sniff {
        static String detectAll(byte[] buf) {
            StringBuilder sb = new StringBuilder();
            sb.append("== Sniff Results ==\n");
            sb.append(png(buf));
            sb.append(elf(buf));
            sb.append(pe(buf));
            sb.append(pcap(buf));
            if (sb.toString().equals("== Sniff Results ==\n")) sb.append("No known headers recognized.\n");
            return sb.toString();
        }

        static String png(byte[] b) {
            if (b.length<24) return "";
            byte[] sig = new byte[]{(byte)137,80,78,71,13,10,26,10};
            for(int i=0;i<8;i++) if (b[i]!=sig[i]) return "";
            // IHDR at 8..(8+4+4+13+4) typically
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
            // DOS MZ
            if (b[0]!='M' || b[1]!='Z') return "";
            // e_lfanew at 0x3C
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
        static int getU16(byte[] b, int off, ByteOrder o){ return o==ByteOrder.LITTLE_ENDIAN ? ((b[off]&0xFF)|((b[off+1]&0xFF)<<8)) : (((b[off]&0xFF)<<8)|(b[off+1]&0xFF)); }
        static int getU32(byte[] b, int off, ByteOrder o){ if(o==ByteOrder.LITTLE_ENDIAN) return (b[off]&0xFF)|((b[off+1]&0xFF)<<8)|((b[off+2]&0xFF)<<16)|((b[off+3]&0xFF)<<24); else return ((b[off]&0xFF)<<24)|((b[off+1]&0xFF)<<16)|((b[off+2]&0xFF)<<8)|(b[off+3]&0xFF); }
    }

    /* ============================ Plugin API ============================ */

    /** Implement this to add new formatters/exporters without touching core code. */
    interface UltraPlugin {
        /** A unique key like "foo" used as:  --foo  or  "export foo out.ext" in shell. */
        String key();
        /** Human-friendly description. */
        String description();
        /** Produce text for given data; may ignore ctx/bpl. */
        String render(Context ctx) throws Exception;
    }

    // Example of registering plugins (add your own here).
    static final Map<String, UltraPlugin> PLUGINS = new LinkedHashMap<>();
    static {
        // Example plugin that renders a simple lowercase hex stream.
        PLUGINS.put("hexstream", new UltraPlugin() {
            public String key(){ return "hexstream"; }
            public String description(){ return "Continuous hex nibbles (no spaces)"; }
            public String render(Context ctx) {
                StringBuilder sb=new StringBuilder(ctx.data.length*2);
                for (byte b: ctx.data) sb.append(String.format("%02x", b&0xFF));
                return sb.toString();
            }
        });
        // You can add more plugins here or split into another file (same package).
    }
}
