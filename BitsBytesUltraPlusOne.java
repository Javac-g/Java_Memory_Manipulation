/*  BitsBytesUltraPlus (Matrix+ Pure Edition)
 *  ---------------------------------------------------------
 *  Single-file. No external deps. Dual mode:
 *    - CLI (args provided)
 *    - REPL (no args) with prompt "Matrix> " and 32 B/line
 *
 *  New (Pure-Java) features:
 *    - Hash: SHA-256 / SHA-1 / MD5  (MessageDigest)
 *    - Sign/Verify: RSA SHA256 (PKCS#8 Private PEM / X.509 Public PEM)
 *    - Metadata: MP3 (ID3v1/v2), PNG (tEXt/iTXt), JPEG (EXIF/XMP headers), PDF (Author/Producer/ModDate)
 *
 *  Previous features retained:
 *    - Dumps: hexdump (Matrix green), binary/oct/dec grids
 *    - Formats: CSV/TSV/Markdown/HTML/JSON/YAML
 *    - Base64/Base32
 *    - Language literals: C/Java/Python/Go
 *    - Bit utilities + endian helpers
 *    - Intel HEX (extended linear), Motorola S-record (auto S1/S2/S3)
 *    - Sniffers: ELF/PE/PNG/PCAP; PCAP packet index
 *    - Plugin API (example: hexstream)
 *
 *  CLI (examples):
 *    java BitsBytesUltraPlus --in file.bin --dump --hash sha256
 *    java BitsBytesUltraPlus --in file.bin --sign private_pkcs8.pem --sig-out sig.bin
 *    java BitsBytesUltraPlus --in file.bin --verify sig.bin public.pem
 *    java BitsBytesUltraPlus --in song.mp3 --meta
 *
 *  REPL (examples):
 *    Matrix> read file.bin
 *    Matrix> hash sha256
 *    Matrix> sign private_pkcs8.pem sig.bin
 *    Matrix> verify sig.bin public.pem
 *    Matrix> meta
 *    Matrix> quit
 */
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BitsBytesUltraPlus {

    /* ============================ MAIN ============================ */

    public static void main(String[] args) {
        try {
            if (args.length == 0) { new Shell().run(); return; }
            CliOptions opt = CliOptions.parse(args);
            byte[] data = loadInput(opt);
            if (data == null) {
                System.err.println("No input. Use --in <file>, --str <text>, or --stdin.");
                System.exit(2);
            }
            Context ctx = new Context(data, opt.color);
            ctx.bytesPerLine = opt.bytesPerLine; // default 32
            runSelectedOutputs(ctx, opt);
        } catch (IllegalArgumentException iae) {
            System.err.println(iae.getMessage()); System.exit(2);
        } catch (IOException ioe) {
            System.err.println("I/O error: " + ioe.getMessage()); System.exit(1);
        } catch (GeneralSecurityException gse) {
            System.err.println("Crypto error: " + gse.getMessage()); System.exit(1);
        }
    }

    /* ======================== Context / IO ======================== */

    static class Context {
        byte[] data;
        boolean color;
        int bytesPerLine = 32;
        Context(byte[] data, boolean color) { this.data = data; this.color = color; }
    }

    private static byte[] loadInput(CliOptions opt) throws IOException {
        if (opt.stdin) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192]; int r;
            while ((r = System.in.read(buf)) != -1) bos.write(buf, 0, r);
            return bos.toByteArray();
        }
        if (opt.inFile != null) return Files.readAllBytes(new File(opt.inFile).toPath());
        if (opt.literalString != null) return opt.literalString.getBytes(StandardCharsets.UTF_8);
        return null;
    }

    private static void runSelectedOutputs(Context ctx, CliOptions opt) throws IOException, GeneralSecurityException {
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

        // sniffers / indexers / metadata
        if (opt.detect) emit(opt, Sniff.detectAll(ctx.data), ".detect.txt");
        if (opt.pcapIndex) emit(opt, Sniff.pcapIndex(ctx.data), ".pcap.txt");
        if (opt.meta) emit(opt, Meta.inspectAll(ctx.data), ".meta.txt");

        // plugin hooks
        for (String k : opt.plugins) {
            UltraPlugin p = PLUGINS.get(k);
            if (p == null) throw new IllegalArgumentException("Unknown plugin: --" + k);
            emit(opt, p.render(ctx), "." + k + ".txt");
        }

        // hashing
        if (opt.hashAlg != null) {
            String report = Crypto.hashReport(ctx.data, opt.hashAlg);
            emit(opt, report, "." + opt.hashAlg + ".hash.txt");
        }

        // sign
        if (opt.signPem != null) {
            byte[] sig = Crypto.signRSA_SHA256(ctx.data, new File(opt.signPem));
            String b64 = Base64.getEncoder().encodeToString(sig);
            String rep = "Signature (RSA SHA256) Base64:\n" + b64 + "\n";
            emit(opt, rep, ".sig.txt");
            if (opt.sigOut != null) try (FileOutputStream fos = new FileOutputStream(opt.sigOut)) { fos.write(sig); }
        }

        // verify
        if (opt.verifySig != null && opt.verifyPub != null) {
            byte[] sig = Crypto.readSigFile(new File(opt.verifySig)); // binary or base64
            boolean ok = Crypto.verifyRSA_SHA256(ctx.data, sig, new File(opt.verifyPub));
            emit(opt, "Verify (RSA SHA256): " + (ok ? "OK" : "FAIL") + "\n", ".verify.txt");
        }

        if (opt.nothingChosen()) emit(opt, Dump.hexDump(ctx, 0, ctx.bytesPerLine, true), ".dump.txt");
    }

    private static void emit(CliOptions opt, String content, String defaultSuffix) throws IOException {
        if (opt.outPrefix == null) { System.out.println(content); }
        else {
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

        boolean dump=false, binTable=false, octGrid=false, decGrid=false;
        boolean json=false,yaml=false,csv=false,tsv=false,md=false,html=false;
        boolean b64=false,b32=false;
        boolean cArr=false,javaArr=false,pyBytes=false,goSlice=false;
        boolean ihex=false,srec=false;
        boolean detect=false, pcapIndex=false, meta=false;

        String hashAlg = null;            // sha256|sha1|md5
        String signPem = null;            // PKCS#8 private
        String sigOut = null;             // binary sig out
        String verifySig = null;          // sig file
        String verifyPub = null;          // X.509 public

        List<String> plugins = new ArrayList<>();
        String outPrefix = null;
        int bytesPerLine = 32;

        static CliOptions parse(String[] args) {
            CliOptions o = new CliOptions();
            for (int i=0;i<args.length;i++) {
                String a = args[i];
                switch(a) {
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
                    case "--pcap-index": o.pcapIndex=true; break;
                    case "--meta": o.meta=true; break;

                    case "--hash": o.hashAlg = need(args, ++i, "--hash <sha256|sha1|md5>").toLowerCase(Locale.ROOT); break;
                    case "--sign": o.signPem = need(args, ++i, "--sign <private_pkcs8.pem>"); break;
                    case "--sig-out": o.sigOut = need(args, ++i, "--sig-out <file>"); break;
                    case "--verify":
                        o.verifySig = need(args, ++i, "--verify <sig.bin> <pub.pem>");
                        o.verifyPub = need(args, ++i, "--verify <sig.bin> <pub.pem>");
                        break;

                    case "--plugin": o.plugins.add(need(args, ++i, "--plugin <name>")); break;

                    case "--out": o.outPrefix = need(args, ++i, "--out <prefix-or-empty>"); break;
                    case "--bpl": o.bytesPerLine = Integer.parseInt(need(args, ++i, "--bpl <int>")); break;

                    case "--help": case "-h": throw new IllegalArgumentException(usage());
                    default:
                        if (a.startsWith("--")) {
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
                    cArr||javaArr||pyBytes||goSlice||ihex||srec||detect||pcapIndex||meta||
                    hashAlg!=null||signPem!=null||verifySig!=null||!plugins.isEmpty());
        }

        static String need(String[] args, int idx, String msg) {
            if (idx >= args.length) throw new IllegalArgumentException(msg);
            return args[idx];
        }

        static String usage() {
            return String.join("\n",
                "BitsBytesUltraPlus (Matrix+ Pure) - single-file ultimate suite",
                "Usage:",
                "  java BitsBytesUltraPlus (--in <file> | --str <text> | --stdin) [formats] [crypto] [--meta] [--out pfx] [--bpl n] [--no-color]",
                "  java BitsBytesUltraPlus    (no args) -> interactive shell",
                "",
                "Formats:",
                "  --dump  --bin  --oct  --dec",
                "  --json  --yaml  --csv  --tsv  --md  --html",
                "  --b64   --b32",
                "  --c     --java  --py   --go",
                "  --ihex  --srec",
                "  --detect     (ELF/PE/PNG/PCAP)",
                "  --pcap-index (pcap packet list)",
                "  --meta       (MP3/PNG/JPEG/PDF metadata quick view)",
                "",
                "Crypto:",
                "  --hash <sha256|sha1|md5>",
                "  --sign <private_pkcs8.pem> [--sig-out sig.bin]",
                "  --verify <sig.bin> <public.pem>",
                "",
                "Options:",
                "  --bpl <n>         bytes per line (default 32)",
                "  --out <prefix>    write outputs to files",
                "  --no-color        disable Matrix ANSI colors"
            );
        }
    }

    /* ========================= SHELL (REPL) ========================= */

    static class Shell {
        private final Scanner sc = new Scanner(System.in);
        private byte[] data = new byte[0];
        private boolean color = true;
        private int bpl = 32;
        private final String PROMPT = "Matrix> ";

        void run() {
            println("BitsBytesUltraPlus Shell (Matrix+ Pure). Type 'help' for commands.");
            while (true) {
                System.out.print(PROMPT);
                if (!sc.hasNextLine()) break;
                String line = sc.nextLine().trim();
                if (line.isEmpty()) continue;
                try {
                    if (line.equalsIgnoreCase("quit") || line.equalsIgnoreCase("exit")) break;
                    if (line.equalsIgnoreCase("help")) { help(); continue; }
                    if (line.startsWith("read ")) { readCmd(line.substring(5).trim()); continue; }

                    // dumps
                    if (line.equals("dump")) { System.out.print(Dump.hexDump(new Context(data,color),0,bpl,true)); continue; }
                    if (line.equals("bin"))  { System.out.print(Dump.binaryTable(new Context(data,color),0,bpl)); continue; }
                    if (line.equals("oct"))  { System.out.print(Dump.octalGrid(new Context(data,color),0,bpl)); continue; }
                    if (line.equals("dec"))  { System.out.print(Dump.decimalGrid(new Context(data,color),0,bpl)); continue; }

                    // formats
                    if (line.equals("json")) { System.out.println(Format.json(data)); continue; }
                    if (line.equals("yaml")) { System.out.println(Format.yaml(data)); continue; }
                    if (line.equals("csv"))  { System.out.println(Format.csv(data,true)); continue; }
                    if (line.equals("tsv"))  { System.out.println(Format.tsv(data,true)); continue; }
                    if (line.equals("md"))   { System.out.println(Format.markdownTable(data)); continue; }
                    if (line.equals("html")) { System.out.println(Format.htmlTable(data)); continue; }

                    // enc
                    if (line.equals("b64")) { System.out.println(Encoding.base64(data)); continue; }
                    if (line.equals("b32")) { System.out.println(Encoding.base32(data)); continue; }

                    // sniff/meta
                    if (line.equals("detect")) { System.out.print(Sniff.detectAll(data)); continue; }
                    if (line.equals("pcap-index")) { System.out.print(Sniff.pcapIndex(data)); continue; }
                    if (line.equals("meta")) { System.out.print(Meta.inspectAll(data)); continue; }

                    // exporters
                    if (line.startsWith("export ")) { exportCmd(line.substring(7).trim()); continue; }

                    // bits
                    if (line.startsWith("getbits ")) { getbitsCmd(line.substring(8).trim()); continue; }
                    if (line.startsWith("setbits ")) { setbitsCmd(line.substring(8).trim()); continue; }

                    // crypto
                    if (line.startsWith("hash ")) { hashCmd(line.substring(5).trim()); continue; }
                    if (line.startsWith("sign ")) { signCmd(line.substring(5).trim()); continue; }
                    if (line.startsWith("verify ")) { verifyCmd(line.substring(7).trim()); continue; }

                    // settings
                    if (line.startsWith("bpl ")) { bpl = Integer.parseInt(line.split("\\s+")[1]); println("bpl="+bpl); continue; }
                    if (line.startsWith("color ")) { color = !line.toLowerCase(Locale.ROOT).contains("off"); println("color="+color); continue; }

                    // plugins
                    if (line.startsWith("plugin ")) { pluginCmd(line.substring(7).trim()); continue; }

                    println("Unknown command. Type 'help'.");
                } catch (Exception e) { println("Error: " + e.getMessage()); }
            }
            println("Bye.");
        }

        void help() {
            println(String.join("\n",
                "Commands:",
                "  read <file>                        Load bytes",
                "  dump | bin | oct | dec             Dumps (Matrix green)",
                "  json | yaml | csv | tsv | md | html",
                "  b64  | b32",
                "  detect | pcap-index | meta         Sniffers & metadata",
                "  export ihex <file> | export srec <file>",
                "  getbits <offset> <len>             Extract bit range",
                "  setbits <offset> <len> <value>     Insert bits",
                "  hash <sha256|sha1|md5>             Print hex + Base64 digest",
                "  sign <private_pkcs8.pem> [sig.bin] Sign data (RSA SHA256); optional output file",
                "  verify <sig.bin> <public.pem>      Verify signature (RSA SHA256)",
                "  plugin <name>                      Run a plugin (e.g., hexstream)",
                "  bpl <n> | color on|off",
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
            String fmt = t[0].toLowerCase(Locale.ROOT), out=t[1];
            String content = fmt.equals("ihex") ? Exporters.intelHexExtended(data, 0)
                             : fmt.equals("srec") ? Exporters.motorolaAuto(data, 0)
                             : null;
            if (content==null){ println("Unknown exporter: "+fmt); return; }
            try (PrintWriter pw = new PrintWriter(out,"UTF-8")) { pw.print(content); }
            println("Wrote "+out);
        }

        void pluginCmd(String name) throws Exception {
            UltraPlugin p = PLUGINS.get(name);
            if (p == null) { println("No such plugin: " + name); return; }
            System.out.println(p.render(new Context(data, color)));
        }

        void getbitsCmd(String rest) {
            String[] t = rest.split("\\s+"); if (t.length<2){ println("Usage: getbits <bitOffset> <bitLen>"); return; }
            int off = Integer.parseInt(t[0]), len=Integer.parseInt(t[1]);
            long v = Bits.extractBits(data, off, len);
            println("0x"+Long.toHexString(v).toUpperCase(Locale.ROOT)+" ("+v+")");
        }

        void setbitsCmd(String rest) {
            String[] t = rest.split("\\s+"); if (t.length<3){ println("Usage: setbits <bitOffset> <bitLen> <value>"); return; }
            int off=Integer.parseInt(t[0]), len=Integer.parseInt(t[1]);
            long val = parseNumber(t[2]); Bits.insertBits(data, off, len, val); println("OK.");
        }

        void hashCmd(String alg) throws GeneralSecurityException {
            System.out.println(Crypto.hashReport(data, alg.toLowerCase(Locale.ROOT)));
        }

        void signCmd(String rest) throws Exception {
            String[] t = rest.split("\\s+");
            if (t.length<1){ println("Usage: sign <private_pkcs8.pem> [sig.bin]"); return; }
            byte[] sig = Crypto.signRSA_SHA256(data, new File(t[0]));
            String b64 = Base64.getEncoder().encodeToString(sig);
            println("Signature (RSA SHA256) Base64:\n"+b64);
            if (t.length>=2) try(FileOutputStream fos=new FileOutputStream(t[1])){ fos.write(sig); println("Saved "+t[1]); }
        }

        void verifyCmd(String rest) throws Exception {
            String[] t = rest.split("\\s+");
            if (t.length<2){ println("Usage: verify <sig.bin> <public.pem>"); return; }
            byte[] sig = Crypto.readSigFile(new File(t[0]));
            boolean ok = Crypto.verifyRSA_SHA256(data, sig, new File(t[1]));
            println("Verify (RSA SHA256): " + (ok ? "OK" : "FAIL"));
        }

        long parseNumber(String s) {
            s = s.trim().toLowerCase(Locale.ROOT);
            if (s.startsWith("0x")) return Long.parseLong(s.substring(2),16);
            if (s.startsWith("0b")) return Long.parseLong(s.substring(2),2);
            return Long.parseLong(s,10);
        }

        void println(String s){ System.out.println(s); }
    }

    /* ===================== Dumps (Matrix color) ===================== */

    static class Dump {
        private static final String RESET="\u001B[0m", DIM="\u001B[2m", GREEN="\u001B[32m", BRIGHT="\u001B[92m";

        static String hexDump(Context ctx, int offset, int bpl, boolean ascii) {
            StringBuilder sb = new StringBuilder(); byte[] d=ctx.data; boolean color=ctx.color;
            for (int i=0;i<d.length;i+=bpl) {
                int len=Math.min(bpl,d.length-i);
                sb.append(color?DIM:"").append(String.format("%08X", i+offset)).append(color?RESET:"").append("  ");
                for (int j=0;j<bpl;j++) {
                    if (j<len) { String oct=String.format("%02X", d[i+j]&0xFF); sb.append(color?GREEN:"").append(oct).append(color?RESET:""); }
                    else sb.append("  ");
                    if ((j&1)==1) sb.append(' ');
                }
                if (ascii) {
                    sb.append(" |");
                    for (int j=0;j<len;j++) {
                        int v=d[i+j]&0xFF; char c=(v>=0x20&&v<=0x7E)?(char)v:'.';
                        sb.append(color?BRIGHT:"").append(c).append(color?RESET:"");
                    }
                    sb.append('|');
                }
                sb.append('\n');
            }
            return sb.toString();
        }
        static String binaryTable(Context ctx,int offset,int bpl){
            StringBuilder sb=new StringBuilder(); boolean color=ctx.color; byte[] d=ctx.data;
            sb.append("Offset    "); for(int b=7;b>=0;b--) sb.append(' ').append(b); sb.append('\n');
            for(int i=0;i<d.length;i+=bpl){ int len=Math.min(bpl,d.length-i);
                for(int j=0;j<len;j++){ byte v=d[i+j]; sb.append(String.format("%08X  ", i+j+offset));
                    for(int bit=7;bit>=0;bit--){ int z=(v>>bit)&1; if(color) sb.append(z==1?BRIGHT:GREEN); sb.append(' ').append(z); if(color) sb.append(RESET); }
                    sb.append('\n'); } }
            return sb.toString();
        }
        static String octalGrid(Context ctx,int offset,int bpl){
            StringBuilder sb=new StringBuilder(); boolean color=ctx.color; byte[] d=ctx.data;
            sb.append("Offset    Octets (base 8)\n");
            for(int i=0;i<d.length;i+=bpl){ int len=Math.min(bpl,d.length-i); sb.append(String.format("%08X  ",i+offset));
                for(int j=0;j<len;j++){ String o=String.format("%03o", d[i+j]&0xFF); sb.append(color?GREEN:"").append(o).append(color?RESET:""); if(j!=len-1) sb.append(' '); } sb.append('\n'); }
            return sb.toString();
        }
        static String decimalGrid(Context ctx,int offset,int bpl){
            StringBuilder sb=new StringBuilder(); boolean color=ctx.color; byte[] d=ctx.data;
            sb.append("Offset    Octets (base 10)\n");
            for(int i=0;i<d.length;i+=bpl){ int len=Math.min(bpl,d.length-i); sb.append(String.format("%08X  ",i+offset));
                for(int j=0;j<len;j++){ String x=String.format("%3d", d[i+j]&0xFF); sb.append(color?GREEN:"").append(x).append(color?RESET:""); if(j!=len-1) sb.append(' '); } sb.append('\n'); }
            return sb.toString();
        }
    }

    /* ===================== Column & Structured ===================== */

    static class Format {
        static String csv(byte[] data, boolean header){ StringBuilder sb=new StringBuilder(); if(header) sb.append("idx,hex,dec,oct,binary\n");
            for(int i=0;i<data.length;i++){ int v=data[i]&0xFF; sb.append(i).append(',').append(String.format("0x%02X",v)).append(',').append(v).append(',').append(String.format("0%03o",v)).append(',').append(toBinary8(v)).append('\n'); } return sb.toString(); }
        static String tsv(byte[] data, boolean header){ StringBuilder sb=new StringBuilder(); if(header) sb.append("idx\thex\tdec\toct\tbinary\n");
            for(int i=0;i<data.length;i++){ int v=data[i]&0xFF; sb.append(i).append('\t').append(String.format("0x%02X",v)).append('\t').append(v).append('\t').append(String.format("0%03o",v)).append('\t').append(toBinary8(v)).append('\n'); } return sb.toString(); }
        static String markdownTable(byte[] data){ StringBuilder sb=new StringBuilder(); sb.append("| Idx | Hex  | Dec | Oct  | Bits      |\n|----:|:----:|----:|:----:|:---------:|\n");
            for(int i=0;i<data.length;i++){ int v=data[i]&0xFF; sb.append(String.format(Locale.ROOT,"| %3d | 0x%02X | %3d | %04o | %s |\n", i,v,v,v,toBinary8(v))); } return sb.toString(); }
        static String htmlTable(byte[] data){ StringBuilder sb=new StringBuilder(); sb.append("<table>\n<thead><tr><th>Idx</th><th>Hex</th><th>Dec</th><th>Oct</th><th>Bits</th></tr></thead>\n<tbody>\n");
            for(int i=0;i<data.length;i++){ int v=data[i]&0xFF; sb.append("<tr><td>").append(i).append("</td><td>").append(String.format("0x%02X",v)).append("</td><td>").append(v).append("</td><td>").append(String.format("%04o",v)).append("</td><td>").append(toBinary8(v)).append("</td></tr>\n"); }
            sb.append("</tbody>\n</table>\n"); return sb.toString(); }
        static String json(byte[] data){ StringBuilder sb=new StringBuilder(); sb.append("["); for(int i=0;i<data.length;i++){ int v=data[i]&0xFF; if(i>0) sb.append(','); sb.append("{\"index\":").append(i).append(",\"hex\":\"").append(String.format("0x%02X",v)).append("\",\"dec\":").append(v).append(",\"oct\":\"").append(String.format("0%03o",v)).append("\",\"bin\":\"").append(toBinary8(v)).append("\"}"); } sb.append("]"); return sb.toString(); }
        static String yaml(byte[] data){ StringBuilder sb=new StringBuilder(); for(int i=0;i<data.length;i++){ int v=data[i]&0xFF; sb.append("- index: ").append(i).append('\n').append("  hex: ").append(String.format("0x%02X",v)).append('\n').append("  dec: ").append(v).append('\n').append("  oct: ").append(String.format("0%03o",v)).append('\n').append("  bin: ").append(toBinary8(v)).append('\n'); } return sb.toString(); }
        private static String toBinary8(int v){ String s=Integer.toBinaryString(v&0xFF); if(s.length()<8) s="00000000".substring(s.length())+s; return s; }
    }

    /* ============================ Encoding ============================ */

    static class Encoding {
        static String base64(byte[] data) { return Base64.getEncoder().encodeToString(data); }
        private static final char[] B32_ALPH="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        static String base32(byte[] bytes){ StringBuilder out=new StringBuilder((bytes.length*8+4)/5); int i=0,index=0,curr,next;
            while(i<bytes.length){ curr=(bytes[i]>=0)?bytes[i]:bytes[i]+256; int digit;
                if(index>3){ next=(i+1<bytes.length)?((bytes[i+1]>=0)?bytes[i+1]:bytes[i+1]+256):0; digit=curr&(0xFF>>index); index=(index+5)%8; digit<<=index; digit|=next>>(8-index); i++; }
                else { digit=(curr>>(8-(index+5)))&0x1F; index=(index+5)%8; if(index==0) i++; }
                out.append(B32_ALPH[digit]); }
            return out.toString(); }
    }

    /* ======================== Language Literals ======================== */

    static class Lang {
        static String cArray(byte[] d,String name){ StringBuilder sb=new StringBuilder(); sb.append("#include <stdint.h>\nconst uint8_t ").append(name).append("[").append(d.length).append("] = {");
            for(int i=0;i<d.length;i++){ if(i%32==0) sb.append("\n  "); sb.append(String.format("0x%02X", d[i]&0xFF)); if(i!=d.length-1) sb.append(", "); } sb.append("\n};\n"); return sb.toString(); }
        static String javaByteArray(byte[] d,String name){ StringBuilder sb=new StringBuilder(); sb.append("byte[] ").append(name).append(" = new byte[] {");
            for(int i=0;i<d.length;i++){ if(i%32==0) sb.append("\n  "); sb.append("(byte)0x").append(String.format("%02X", d[i]&0xFF)); if(i!=d.length-1) sb.append(", "); } sb.append("\n};\n"); return sb.toString(); }
        static String pythonBytes(byte[] d,String name){ StringBuilder sb=new StringBuilder(); sb.append(name).append(" = bytes([");
            for(int i=0;i<d.length;i++){ if(i%32==0) sb.append("\n  "); sb.append(d[i]&0xFF); if(i!=d.length-1) sb.append(", "); } sb.append("\n])\n"); return sb.toString(); }
        static String goByteSlice(byte[] d,String name){ StringBuilder sb=new StringBuilder(); sb.append(name).append(" := []byte{");
            for(int i=0;i<d.length;i++){ if(i%32==0) sb.append("\n  "); sb.append(String.format("0x%02X", d[i]&0xFF)); if(i!=d.length-1) sb.append(", "); } sb.append("\n}\n"); return sb.toString(); }
    }

    /* ============================ Bits / Words ============================ */

    static class Bits {
        static int getBits(int value,int from,int len){ if(len<=0||from<0||from+len>32) throw new IllegalArgumentException("range"); int mask=(len==32)?-1:((1<<len)-1); return (value>>>from)&mask; }
        static int setBits(int base,int from,int len,int bits){ if(len<=0||from<0||from+len>32) throw new IllegalArgumentException("range"); int mask=(len==32)?-1:((1<<len)-1); int cleared=base&~(mask<<from); return cleared|((bits&mask)<<from); }
        static long extractBits(byte[] d,int bitOffset,int bitLength){ if(bitLength<=0||bitLength>64) throw new IllegalArgumentException("bitLength 1..64"); if(bitOffset<0) throw new IllegalArgumentException("bitOffset >= 0");
            int byteIndex=bitOffset/8, intra=bitOffset%8, needed=(intra+bitLength+7)/8; if(byteIndex+needed>d.length) throw new IllegalArgumentException("range exceeds length");
            long acc=0; for(int i=0;i<needed;i++) acc=(acc<<8)|(d[byteIndex+i]&0xFFL); int shiftRight=(needed*8)-intra-bitLength; return (acc>>>shiftRight)&((bitLength==64)?-1L:((1L<<bitLength)-1L)); }
        static void insertBits(byte[] d,int bitOffset,int bitLength,long value){ if(bitLength<=0||bitLength>64) throw new IllegalArgumentException("bitLength 1..64"); if(bitOffset<0) throw new IllegalArgumentException("bitOffset >= 0");
            int byteIndex=bitOffset/8,intra=bitOffset%8,needed=(intra+bitLength+7)/8; if(byteIndex+needed>d.length) throw new IllegalArgumentException("range exceeds length");
            long mask=(bitLength==64)?-1L:((1L<<bitLength)-1L); long cur=0; for(int i=0;i<needed;i++) cur=(cur<<8)|(d[byteIndex+i]&0xFFL);
            int shiftRight=(needed*8)-intra-bitLength; long cleared=cur&~(mask<<shiftRight); long with=cleared|((value&mask)<<shiftRight); for(int i=needed-1;i>=0;i--){ d[byteIndex+i]=(byte)(with&0xFF); with>>>=8; } }
    }

    static class Words {
        static byte[] toBytes(short v,ByteOrder o){ ByteBuffer b=ByteBuffer.allocate(2).order(o); b.putShort(v); return b.array(); }
        static byte[] toBytes(int v,ByteOrder o){ ByteBuffer b=ByteBuffer.allocate(4).order(o); b.putInt(v); return b.array(); }
        static byte[] toBytes(long v,ByteOrder o){ ByteBuffer b=ByteBuffer.allocate(8).order(o); b.putLong(v); return b.array(); }
        static short toShort(byte[] a,int off,ByteOrder o){ return ByteBuffer.wrap(a,off,2).order(o).getShort(); }
        static int toInt(byte[] a,int off,ByteOrder o){ return ByteBuffer.wrap(a,off,4).order(o).getInt(); }
        static long toLong(byte[] a,int off,ByteOrder o){ return ByteBuffer.wrap(a,off,8).order(o).getLong(); }
    }

    /* ============================ Exporters ============================ */

    static class Exporters {
        static String intelHexExtended(byte[] data,int base){
            int rec=16,lastHigh=-1; StringBuilder sb=new StringBuilder();
            for(int i=0;i<data.length;i+=rec){ int len=Math.min(rec,data.length-i); int abs=base+i, high=(abs>>>16)&0xFFFF, low=abs&0xFFFF;
                if(high!=lastHigh){ int csum=2+0+4+((high>>8)&0xFF)+(high&0xFF); csum=((~csum+1)&0xFF); sb.append(':').append(String.format("%02X%04X%02X%04X%02X",2,0,4,high,csum)).append('\n'); lastHigh=high; }
                int checksum=len+((low>>8)&0xFF)+(low&0xFF); sb.append(':').append(String.format("%02X%04X%02X",len,low,0));
                for(int j=0;j<len;j++){ int b=data[i+j]&0xFF; checksum=(checksum+b)&0xFF; sb.append(String.format("%02X",b)); }
                checksum=((~checksum+1)&0xFF); sb.append(String.format("%02X",checksum)).append('\n'); }
            sb.append(":00000001FF\n"); return sb.toString(); }
        static String motorolaAuto(byte[] data,int base){
            int rec=16; StringBuilder sb=new StringBuilder(); int max=base+Math.max(0,data.length-1); int type,ab;
            if(max<=0xFFFF){ type=1; ab=2; } else if(max<=0xFFFFFF){ type=2; ab=3; } else { type=3; ab=4; }
            for(int i=0;i<data.length;i+=rec){ int len=Math.min(rec,data.length-i), addr=base+i, bc=len+ab+1, sum=bc; sb.append('S').append(type).append(String.format("%02X",bc));
                for(int k=ab-1;k>=0;k--){ int v=(addr>>(k*8))&0xFF; sb.append(String.format("%02X",v)); sum=(sum+v)&0xFF; }
                for(int j=0;j<len;j++){ int b=data[i+j]&0xFF; sb.append(String.format("%02X",b)); sum=(sum+b)&0xFF; }
                int cks=(~sum)&0xFF; sb.append(String.format("%02X",cks)).append('\n'); }
            switch(type){ case 1: sb.append("S9030000FC\n"); break; case 2: sb.append("S804000000FB\n"); break; default: sb.append("S70500000000FA\n"); }
            return sb.toString(); }
    }

    /* ============================ Sniffers / PCAP Index ============================ */

    static class Sniff {
        static String detectAll(byte[] b){
            StringBuilder sb=new StringBuilder(); sb.append("== Sniff Results ==\n"); boolean any=false; String s;
            if(!(s=png(b)).isEmpty()){ sb.append(s); any=true; } if(!(s=elf(b)).isEmpty()){ sb.append(s); any=true; } if(!(s=pe(b)).isEmpty()){ sb.append(s); any=true; } if(!(s=pcap(b)).isEmpty()){ sb.append(s); any=true; }
            if(!any) sb.append("No known headers recognized.\n"); return sb.toString(); }
        static String png(byte[] b){ if(b.length<24) return ""; byte[] sig=new byte[]{(byte)137,80,78,71,13,10,26,10}; for(int i=0;i<8;i++) if(b[i]!=sig[i]) return "";
            if(b.length<33) return "PNG: signature OK, too short to read IHDR\n";
            int w=(int)((b[16]&0xFFL)<<24|(b[17]&0xFFL)<<16|(b[18]&0xFFL)<<8|(b[19]&0xFFL));
            int h=(int)((b[20]&0xFFL)<<24|(b[21]&0xFFL)<<16|(b[22]&0xFFL)<<8|(b[23]&0xFFL));
            int bit=b[24]&0xFF, ct=b[25]&0xFF; return String.format("PNG: %dx%d, bitDepth=%d, colorType=%d\n", w,h,bit,ct); }
        static String elf(byte[] b){ if(b.length<52) return ""; if(b[0]!=0x7F||b[1]!='E'||b[2]!='L'||b[3]!='F') return ""; int cls=b[4]&0xFF, endian=b[5]&0xFF;
            int type=((b[16]&0xFF)|((b[17]&0xFF)<<8)), mach=((b[18]&0xFF)|((b[19]&0xFF)<<8));
            return String.format("ELF: class=%s, endian=%s, type=0x%04X, machine=0x%04X\n", (cls==1?"32-bit":cls==2?"64-bit":"?"), (endian==1?"little":endian==2?"big":"?"), type, mach); }
        static String pe(byte[] b){ if(b.length<0x40) return ""; if(b[0]!='M'||b[1]!='Z') return ""; int peOff=((b[0x3C]&0xFF)|((b[0x3D]&0xFF)<<8)|((b[0x3E]&0xFF)<<16)|((b[0x3F]&0xFF)<<24));
            if(peOff+6>=b.length) return "PE: MZ found, PE header beyond file size\n"; if(!(b[peOff]=='P'&&b[peOff+1]=='E'&&b[peOff+2]==0&&b[peOff+3]==0)) return "PE: MZ found, PE signature missing\n";
            int mach=((b[peOff+4]&0xFF)|((b[peOff+5]&0xFF)<<8)), secs=((b[peOff+6]&0xFF)|((b[peOff+7]&0xFF)<<8)); return String.format("PE: machine=0x%04X, sections=%d\n", mach, secs); }
        static String pcap(byte[] b){ if(b.length<24) return ""; int magic=(b[0]&0xFF)|((b[1]&0xFF)<<8)|((b[2]&0xFF)<<16)|((b[3]&0xFF)<<24);
            boolean le=(magic==0xA1B2C3D4||magic==0xA1B23C4D), be=(magic==0xD4C3B2A1||magic==0x4D3CB2A1); if(!le&&!be) return ""; ByteOrder o=le?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN;
            int vM=getU16(b,4,o), vN=getU16(b,6,o), snap=getU32(b,16,o), link=getU32(b,20,o);
            return String.format("PCAP: endian=%s, v=%d.%d, snaplen=%d, linktype=%d\n", le?"LE":"BE", vM, vN, snap, link); }
        static String pcapIndex(byte[] b){ if(b.length<24) return "PCAP Index: Not a pcap or too short.\n"; int magic=(b[0]&0xFF)|((b[1]&0xFF)<<8)|((b[2]&0xFF)<<16)|((b[3]&0xFF)<<24);
            boolean le=(magic==0xA1B2C3D4||magic==0xA1B23C4D)||false, be=(magic==0xD4C3B2A1||magic==0x4D3CB2A1); if(!le&&!be) return "PCAP Index: Not a recognized pcap magic.\n"; ByteOrder o=le?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN;
            int off=24, idx=0; StringBuilder sb=new StringBuilder(); sb.append("== PCAP Packet Index ==\n").append(String.format("Endian=%s\n", le?"LE":"BE"))
              .append("Idx | FileOff |    TS (epoch)          | InclLen | OrigLen\n").append("----+---------+------------------------+---------+--------\n");
            while(off+16<=b.length){ long tsS=getU32L(b,off,o), tsU=getU32L(b,off+4,o), incl=getU32L(b,off+8,o), orig=getU32L(b,off+12,o), fileOff=off;
                long epochNs=tsS*1_000_000_000L + tsU*1000L;
                sb.append(String.format(Locale.ROOT,"%3d | %7d | %s | %7d | %7d\n", idx, fileOff, Instant.ofEpochMilli(epochNs/1_000_000L), incl, orig));
                off+=16; if(off+incl>b.length){ sb.append("(truncated)\n"); break; } off+= (int)incl; idx++; }
            return sb.toString(); }
        static int getU16(byte[] b,int off,ByteOrder o){ return o==ByteOrder.LITTLE_ENDIAN?((b[off]&0xFF)|((b[off+1]&0xFF)<<8)):(((b[off]&0xFF)<<8)|(b[off+1]&0xFF)); }
        static int getU32(byte[] b,int off,ByteOrder o){ return o==ByteOrder.LITTLE_ENDIAN?(b[off]&0xFF)|((b[off+1]&0xFF)<<8)|((b[off+2]&0xFF)<<16)|((b[off+3]&0xFF)<<24)
                :((b[off]&0xFF)<<24)|((b[off+1]&0xFF)<<16)|((b[off+2]&0xFF)<<8)|(b[off+3]&0xFF); }
        static long getU32L(byte[] b,int off,ByteOrder o){ return getU32(b,off,o)&0xFFFFFFFFL; }
    }

    /* ============================ Metadata ============================ */

    static class Meta {
        static String inspectAll(byte[] buf){
            StringBuilder sb=new StringBuilder(); sb.append("== Metadata Preview ==\n");
            sb.append(mp3(buf)); sb.append(pngText(buf)); sb.append(jpegHeaders(buf)); sb.append(pdfQuick(buf));
            return sb.toString();
        }

        // --- MP3 ID3v1 + minimal ID3v2 ---
        static String mp3(byte[] b){
            StringBuilder sb=new StringBuilder();
            // ID3v2
            if (b.length>=10 && b[0]=='I'&&b[1]=='D'&&b[2]=='3') {
                int size = synchsafeToInt(b[6],b[7],b[8],b[9]);
                sb.append("MP3: ID3v2 detected, size=").append(size).append("\n");
                int pos = 10; int end = Math.min(b.length, 10+size);
                while (pos+10<=end) {
                    String id = new String(b, pos, 4, StandardCharsets.ISO_8859_1);
                    if (id.trim().isEmpty() || !id.matches("[A-Z0-9]{4}")) break;
                    int frameSize = ((b[pos+4]&0xFF)<<24)|((b[pos+5]&0xFF)<<16)|((b[pos+6]&0xFF)<<8)|(b[pos+7]&0xFF);
                    if (frameSize<=0 || pos+10+frameSize> end) break;
                    // only read small frames to avoid spam
                    if (frameSize>0 && frameSize<=512) {
                        byte enc = b[pos+10];
                        String val = decodeId3(enc, b, pos+11, frameSize-1);
                        if (id.equals("TIT2")||id.equals("TPE1")||id.equals("TALB")||id.equals("TCON")||id.equals("TCOP")||id.equals("TDRC")||id.equals("TYER"))
                            sb.append("  ").append(id).append(": ").append(val).append("\n");
                    }
                    pos += 10 + frameSize;
                }
            }
            // ID3v1
            if (b.length>=128) {
                int base=b.length-128;
                if (b[base]=='T' && b[base+1]=='A' && b[base+2]=='G') {
                    String title = trimNulls(new String(b, base+3, 30, StandardCharsets.ISO_8859_1));
                    String artist = trimNulls(new String(b, base+33, 30, StandardCharsets.ISO_8859_1));
                    String album = trimNulls(new String(b, base+63, 30, StandardCharsets.ISO_8859_1));
                    String year = trimNulls(new String(b, base+93, 4, StandardCharsets.ISO_8859_1));
                    sb.append("MP3: ID3v1: ").append(title).append(" / ").append(artist).append(" / ").append(album).append(" (").append(year).append(")\n");
                }
            }
            return sb.toString();
        }
        static int synchsafeToInt(byte b0, byte b1, byte b2, byte b3) {
            return ((b0 & 0x7F) << 21) | ((b1 & 0x7F) << 14) | ((b2 & 0x7F) << 7) | (b3 & 0x7F);
        }
        static String decodeId3(byte enc, byte[] arr, int off, int len) {
            try {
                if (enc==0) return trimNulls(new String(arr, off, len, StandardCharsets.ISO_8859_1));
                if (enc==1) return trimNulls(new String(arr, off, len, "UTF-16"));
                if (enc==2) return trimNulls(new String(arr, off, len, "UTF-16BE"));
                if (enc==3) return trimNulls(new String(arr, off, len, StandardCharsets.UTF_8));
            } catch (Exception ignored) {}
            return trimNulls(new String(arr, off, len, StandardCharsets.ISO_8859_1));
        }
        static String trimNulls(String s){ int i=s.indexOf(0); return i>=0 ? s.substring(0,i) : s.trim(); }

        // --- PNG textual chunks ---
        static String pngText(byte[] b){
            StringBuilder sb=new StringBuilder();
            byte[] sig=new byte[]{(byte)137,80,78,71,13,10,26,10}; if(b.length<8) return sb.toString();
            for(int i=0;i<8;i++) if(b[i]!=sig[i]) return sb.toString();
            int pos=8;
            while(pos+12<=b.length){
                int len=((b[pos]&0xFF)<<24)|((b[pos+1]&0xFF)<<16)|((b[pos+2]&0xFF)<<8)|(b[pos+3]&0xFF);
                String type= new String(b, pos+4, 4, StandardCharsets.ISO_8859_1);
                if (pos+12+len>b.length) break;
                if (("tEXt".equals(type) || "iTXt".equals(type)) && len>0 && len<=4096) {
                    String s = new String(b, pos+8, len, StandardCharsets.ISO_8859_1);
                    sb.append("PNG ").append(type).append(": ").append(s.replace('\0', '=')).append("\n");
                }
                pos += 12+len;
                if ("IEND".equals(type)) break;
            }
            return sb.toString();
        }

        // --- JPEG EXIF/XMP headers ---
        static String jpegHeaders(byte[] b){
            if (b.length<4 || (b[0]&0xFF)!=0xFF || (b[1]&0xFF)!=0xD8) return "";
            StringBuilder sb=new StringBuilder(); int pos=2;
            while (pos+4<=b.length) {
                if ((b[pos]&0xFF)!=0xFF) break;
                int marker = b[pos+1]&0xFF; if (marker==0xDA) break; // SOS
                int len = ((b[pos+2]&0xFF)<<8)|(b[pos+3]&0xFF); if (len<2 || pos+2+len> b.length) break;
                if (marker==0xE1) {
                    // APP1
                    if (len>=8 && pos+4+6 <= b.length) {
                        String head = new String(b, pos+4, Math.min(29, len-2), StandardCharsets.ISO_8859_1);
                        if (head.startsWith("Exif")) sb.append("JPEG: EXIF header len=").append(len).append("\n");
                        if (head.contains("http://ns.adobe.com/xap/1.0/")) sb.append("JPEG: XMP header len=").append(len).append("\n");
                    }
                }
                pos += 2+len;
            }
            return sb.toString();
        }

        // --- PDF quick trailer scan (/Author, /Producer, /ModDate) ---
        static String pdfQuick(byte[] b){
            String s = new String(b, 0, Math.min(b.length, 200_000), StandardCharsets.ISO_8859_1);
            if (!s.contains("%PDF")) return "";
            StringBuilder sb = new StringBuilder("PDF: quick scan\n");
            findPdfField(sb, s, "/Author");
            findPdfField(sb, s, "/Producer");
            findPdfField(sb, s, "/ModDate");
            return sb.toString();
        }
        static void findPdfField(StringBuilder sb, String s, String key){
            Matcher m = Pattern.compile(Pattern.quote(key)+"\\s*\\((.*?)\\)").matcher(s);
            if (m.find()) sb.append("  ").append(key.substring(1)).append(": ").append(m.group(1)).append("\n");
        }
    }

    /* ============================ Crypto (Pure Java) ============================ */

    static class Crypto {
        static String hashReport(byte[] data, String alg) throws GeneralSecurityException {
            String jalg = switch (alg) {
                case "sha256" -> "SHA-256";
                case "sha1" -> "SHA-1";
                case "md5" -> "MD5";
                default -> throw new GeneralSecurityException("Unknown hash alg: " + alg);
            };
            MessageDigest md = MessageDigest.getInstance(jalg);
            byte[] dig = md.digest(data);
            return "Hash " + alg.toUpperCase(Locale.ROOT) + ":\nHEX  " + toHex(dig) + "\nB64  " + Base64.getEncoder().encodeToString(dig) + "\n";
        }

        static byte[] signRSA_SHA256(byte[] data, File pkcs8Pem) throws Exception {
            PrivateKey priv = readPrivateKeyPKCS8(pkcs8Pem);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(priv); sig.update(data); return sig.sign();
        }

        static boolean verifyRSA_SHA256(byte[] data, byte[] signature, File pubPem) throws Exception {
            PublicKey pub = readPublicKeyX509(pubPem);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(pub); sig.update(data);
            return sig.verify(signature);
        }

        static PrivateKey readPrivateKeyPKCS8(File pem) throws Exception {
            String p = Files.readString(pem.toPath(), StandardCharsets.US_ASCII);
            String base = extractPemBlock(p, "PRIVATE KEY");
            byte[] der = Base64.getMimeDecoder().decode(base);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        }

        static PublicKey readPublicKeyX509(File pem) throws Exception {
            String p = Files.readString(pem.toPath(), StandardCharsets.US_ASCII);
            String base = extractPemBlock(p, "PUBLIC KEY");
            byte[] der = Base64.getMimeDecoder().decode(base);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        }

        static String extractPemBlock(String pem, String type) throws GeneralSecurityException {
            String start = "-----BEGIN " + type + "-----";
            String end = "-----END " + type + "-----";
            int s = pem.indexOf(start), e = pem.indexOf(end);
            if (s<0 || e<0) throw new GeneralSecurityException(type + " PEM block not found");
            String body = pem.substring(s + start.length(), e).replaceAll("\\s", "");
            if (body.isEmpty()) throw new GeneralSecurityException("Empty PEM block");
            return body;
        }

        static byte[] readSigFile(File f) throws IOException {
            byte[] raw = Files.readAllBytes(f.toPath());
            // if looks ASCII base64, decode; else return raw
            boolean ascii = true;
            for (byte b : raw) { int c=b&0xFF; if (c<0x20 && c!=0x09 && c!=0x0A && c!=0x0D) { ascii=false; break; } }
            if (ascii) {
                String s = new String(raw, StandardCharsets.US_ASCII).trim();
                if (s.matches("[A-Za-z0-9+/=\\s]+")) {
                    try { return Base64.getMimeDecoder().decode(s); } catch (IllegalArgumentException ignored) {}
                }
            }
            return raw;
        }

        static String toHex(byte[] a){ StringBuilder sb=new StringBuilder(a.length*2); for(byte b:a) sb.append(String.format("%02x", b&0xFF)); return sb.toString(); }
    }

    /* ============================ Plugin API ============================ */

    interface UltraPlugin { String key(); String description(); String render(Context ctx) throws Exception; }

    static final Map<String, UltraPlugin> PLUGINS = new LinkedHashMap<>();
    static {
        PLUGINS.put("hexstream", new UltraPlugin() {
            public String key(){ return "hexstream"; }
            public String description(){ return "Continuous hex nibbles (no spaces), lowercase"; }
            public String render(Context ctx){ StringBuilder sb=new StringBuilder(ctx.data.length*2); for(byte b:ctx.data) sb.append(String.format("%02x", b&0xFF)); return sb.toString(); }
        });
    }
}
