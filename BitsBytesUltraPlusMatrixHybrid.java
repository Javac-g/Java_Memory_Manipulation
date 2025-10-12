import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BitsBytesUltraPlus Matrix Hybrid+ (Java 21)
 * ------------------------------------------
 * Dual-mode: CLI if args; REPL "Matrix>" if not.
 * Monochrome by default. Toggle ANSI in REPL:  `color on|off`
 *
 * Features:
 *  - Hex/Binary/Octal/Decimal dumps (32 bytes/line default)
 *  - CSV/TSV/JSON/YAML/Markdown/HTML exporters
 *  - Base64/Base32
 *  - Language literals (C/Java/Python/Go)
 *  - Intel HEX (with ELA) + Motorola S-records (S1/2/3 auto)
 *  - Sniffers: PNG/ELF/PE/PCAP (with packet index), MP3 (ID3), JPEG/PDF quick meta
 *  - Crypto (built-in): SHA-256/SHA-1/MD5, RSA-SHA256, AES-GCM
 *  - Hybrid crypto plugins via CryptoPluginsMatrixHybrid (scans ~/.matrix/plugins)
 *
 * Quick REPL:
 *   Matrix> read file.bin
 *   Matrix> dump
 *   Matrix> hash sha256
 *   Matrix> sign private_pkcs8.pem sig.bin
 *   Matrix> verify sig.bin public.pem
 *   Matrix> crypto list
 *   Matrix> crypto use ed25519
 *   Matrix> encrypt aesgcm key.bin iv.bin out.enc
 *   Matrix> decrypt aesgcm key.bin iv.bin out.dec
 *   Matrix> meta
 *   Matrix> quit
 */
public class BitsBytesUltraPlusMatrixHybrid {

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
            // Initialize plugin env (register builtins; load external jars)
            CryptoPluginsMatrixHybrid.bootstrap();

            // Apply crypto provider selection if passed
            if (opt.cryptoList) { HybridCrypto.listProviders(); return; }
            if (opt.cryptoUse != null) HybridCrypto.use(opt.cryptoUse);

            // Dumps / tables
            if (opt.dump) System.out.print(Dump.hexDump(new Context(data, opt.color), 0, opt.bpl, true));
            if (opt.bin)  System.out.print(Dump.binaryTable(new Context(data, opt.color), 0, opt.bpl));
            if (opt.oct)  System.out.print(Dump.octalGrid(new Context(data, opt.color), 0, opt.bpl));
            if (opt.dec)  System.out.print(Dump.decimalGrid(new Context(data, opt.color), 0, opt.bpl));

            // Structured
            if (opt.json) System.out.println(Format.json(data));
            if (opt.yaml) System.out.println(Format.yaml(data));
            if (opt.csv)  System.out.println(Format.csv(data, true));
            if (opt.tsv)  System.out.println(Format.tsv(data, true));
            if (opt.md)   System.out.println(Format.markdownTable(data));
            if (opt.html) System.out.println(Format.htmlTable(data));

            // Encodings
            if (opt.b64)  System.out.println(Encoding.base64(data));
            if (opt.b32)  System.out.println(Encoding.base32(data));

            // Lang literals
            if (opt.cArr)    System.out.println(Lang.cArray(data, "data"));
            if (opt.javaArr) System.out.println(Lang.javaByteArray(data, "data"));
            if (opt.pyBytes) System.out.println(Lang.pythonBytes(data, "data"));
            if (opt.goSlice) System.out.println(Lang.goByteSlice(data, "data"));

            // Exporters
            if (opt.ihex) System.out.println(Exporters.intelHexExtended(data, 0));
            if (opt.srec) System.out.println(Exporters.motorolaAuto(data, 0));

            // Sniffers/Meta
            if (opt.detect) System.out.print(Sniff.detectAll(data));
            if (opt.pcapIndex) System.out.print(Sniff.pcapIndex(data));
            if (opt.meta) System.out.print(Meta.inspectAll(data));

            // Crypto (hybrid)
            if (opt.hashAlg != null) System.out.println(HybridCrypto.hash(opt.hashAlg, data));
            if (opt.signPem != null) {
                byte[] sig = HybridCrypto.sign(data, new File(opt.signPem));
                if (opt.sigOut != null) try (FileOutputStream fos = new FileOutputStream(opt.sigOut)) { fos.write(sig); }
                System.out.println("Signature (base64): " + Base64.getEncoder().encodeToString(sig));
            }
            if (opt.verifySig != null && opt.verifyPub != null) {
                boolean ok = HybridCrypto.verify(data, new File(opt.verifySig), new File(opt.verifyPub));
                System.out.println("Verify: " + (ok ? "OK" : "FAIL"));
            }
            if (opt.encMode != null) {
                if ("encrypt".equals(opt.encMode)) {
                    byte[] out = HybridCrypto.encrypt(opt.cipher, data, opt.keyFile, opt.ivFile);
                    String outFile = opt.outFile != null ? opt.outFile : "out.enc";
                    Files.write(Path.of(outFile), out);
                    System.out.println("Encrypted -> " + outFile);
                } else if ("decrypt".equals(opt.encMode)) {
                    byte[] out = HybridCrypto.decrypt(opt.cipher, data, opt.keyFile, opt.ivFile);
                    String outFile = opt.outFile != null ? opt.outFile : "out.dec";
                    Files.write(Path.of(outFile), out);
                    System.out.println("Decrypted -> " + outFile);
                }
            }

            // Default if nothing chosen
            if (opt.nothingChosen()) System.out.print(Dump.hexDump(new Context(data, opt.color), 0, opt.bpl, true));

        } catch (Exception e) {
            System.err.println("[ERR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    /* ============================ CLI ============================ */

    static class CliOptions {
        String inFile = null, literalString = null;
        boolean stdin = false, color = false; // monochrome default; toggle in REPL
        int bpl = 32;

        boolean dump=false, bin=false, oct=false, dec=false;
        boolean json=false,yaml=false,csv=false,tsv=false,md=false,html=false;
        boolean b64=false,b32=false;
        boolean cArr=false,javaArr=false,pyBytes=false,goSlice=false;
        boolean ihex=false, srec=false;
        boolean detect=false, pcapIndex=false, meta=false;

        // Hybrid crypto
        boolean cryptoList=false; String cryptoUse=null;
        String hashAlg=null; String signPem=null, sigOut=null, verifySig=null, verifyPub=null;
        String encMode=null, cipher=null, keyFile=null, ivFile=null, outFile=null;

        static CliOptions parse(String[] a) {
            CliOptions o = new CliOptions();
            for (int i=0;i<a.length;i++) {
                String s = a[i];
                switch (s) {
                    case "--in" -> o.inFile = need(a, ++i, "--in <file>");
                    case "--str" -> o.literalString = need(a, ++i, "--str <text>");
                    case "--stdin" -> o.stdin = true;
                    case "--color" -> o.color = true;
                    case "--bpl" -> o.bpl = Integer.parseInt(need(a, ++i, "--bpl <int>"));

                    case "--dump" -> o.dump=true;
                    case "--bin" -> o.bin=true;
                    case "--oct" -> o.oct=true;
                    case "--dec" -> o.dec=true;

                    case "--json" -> o.json=true;
                    case "--yaml" -> o.yaml=true;
                    case "--csv" -> o.csv=true;
                    case "--tsv" -> o.tsv=true;
                    case "--md" -> o.md=true;
                    case "--html" -> o.html=true;

                    case "--b64" -> o.b64=true;
                    case "--b32" -> o.b32=true;

                    case "--c" -> o.cArr=true;
                    case "--java" -> o.javaArr=true;
                    case "--py" -> o.pyBytes=true;
                    case "--go" -> o.goSlice=true;

                    case "--ihex" -> o.ihex=true;
                    case "--srec" -> o.srec=true;

                    case "--detect" -> o.detect=true;
                    case "--pcap-index" -> o.pcapIndex=true;
                    case "--meta" -> o.meta=true;

                    // Crypto
                    case "--crypto-list" -> o.cryptoList=true;
                    case "--crypto-use" -> o.cryptoUse = need(a, ++i, "--crypto-use <name>");
                    case "--hash" -> o.hashAlg = need(a, ++i, "--hash <sha256|sha1|md5|blake3|argon2id|ed25519-digest>");
                    case "--sign" -> o.signPem = need(a, ++i, "--sign <private_pkcs8.pem>");
                    case "--sig-out" -> o.sigOut = need(a, ++i, "--sig-out <file>");
                    case "--verify" -> { o.verifySig = need(a, ++i, "--verify <sig.bin> <pub.pem>"); o.verifyPub = need(a, ++i, "<pub.pem>"); }
                    case "--encrypt" -> { o.encMode="encrypt"; o.cipher = need(a, ++i, "--encrypt <aesgcm>"); o.keyFile=need(a, ++i, "<key.bin>"); o.ivFile=need(a, ++i, "<iv.bin>"); o.outFile=(i+1<a.length && !a[i+1].startsWith("--"))? a[++i]: null; }
                    case "--decrypt" -> { o.encMode="decrypt"; o.cipher = need(a, ++i, "--decrypt <aesgcm>"); o.keyFile=need(a, ++i, "<key.bin>"); o.ivFile=need(a, ++i, "<iv.bin>"); o.outFile=(i+1<a.length && !a[i+1].startsWith("--"))? a[++i]: null; }

                    case "--help", "-h" -> throw new IllegalArgumentException(usage());
                    default -> throw new IllegalArgumentException("Unknown: " + s + "\n\n" + usage());
                }
            }
            if ((o.inFile!=null?1:0) + (o.literalString!=null?1:0) + (o.stdin?1:0) > 1)
                throw new IllegalArgumentException("Use only one of --in, --str, or --stdin.");
            return o;
        }

        boolean nothingChosen() {
            return !(dump||bin||oct||dec||json||yaml||csv||tsv||md||html||b64||b32||cArr||javaArr||pyBytes||goSlice||
                     ihex||srec||detect||pcapIndex||meta||cryptoList||cryptoUse!=null||hashAlg!=null||signPem!=null||verifySig!=null||encMode!=null);
        }

        static String need(String[] a, int i, String msg){ if (i>=a.length) throw new IllegalArgumentException(msg); return a[i]; }

        static String usage() {
            return String.join("\n",
              "BitsBytesUltraPlusMatrixHybrid (Java 21)",
              "Usage:",
              "  java BitsBytesUltraPlusMatrixHybrid (--in <file> | --str <text> | --stdin) [opts]",
              "",
              "Views: --dump --bin --oct --dec  [--bpl N] [--color]",
              "Tables: --csv --tsv --json --yaml --md --html",
              "Enc:    --b64 --b32",
              "Lang:   --c --java --py --go",
              "Export: --ihex --srec",
              "Sniff:  --detect --pcap-index --meta",
              "",
              "Crypto:",
              "  --crypto-list | --crypto-use <name>",
              "  --hash <sha256|sha1|md5|blake3|argon2id|ed25519-digest>",
              "  --sign <private_pkcs8.pem> [--sig-out sig.bin]",
              "  --verify <sig.bin> <public.pem>",
              "  --encrypt aesgcm <key.bin> <iv.bin> [out.enc]",
              "  --decrypt aesgcm <key.bin> <iv.bin> [out.dec]"
            );
        }
    }

    /* ======================== Context / Color ======================== */

    static class Context {
        byte[] data; boolean color; int bytesPerLine = 32;
        Context(byte[] data, boolean color){ this.data=data; this.color=color; }
    }
    static final class Ansi {
        static final String RESET = "\u001B[0m";
        static final String DIM   = "\u001B[2m";
        static final String GREEN = "\u001B[32m";
        static final String BRIGHT= "\u001B[92m";
        static String apply(boolean on, String code, String s){ return on ? code + s + RESET : s; }
    }

    /* ========================= SHELL (REPL) ========================= */

    static class Shell {
        private final Scanner sc = new Scanner(System.in);
        private byte[] data = new byte[0];
        private boolean color = false;      // monochrome default
        private int bpl = 32;
        private final String PROMPT = "Matrix> ";

        void run() {
            System.out.println("BitsBytesUltraPlus Matrix Hybrid+. Type 'help'.");
            try { CryptoPluginsMatrixHybrid.bootstrap(); } catch (Exception e) { System.out.println("Plugin bootstrap: "+e.getMessage()); }
            while (true) {
                System.out.print(PROMPT);
                if (!sc.hasNextLine()) break;
                String line = sc.nextLine().trim();
                if (line.isEmpty()) continue;
                try {
                    if (line.equalsIgnoreCase("quit") || line.equalsIgnoreCase("exit")) break;
                    if (line.equalsIgnoreCase("help")) { help(); continue; }

                    if (line.startsWith("read ")) { data = Files.readAllBytes(Path.of(line.substring(5).trim())); System.out.println("Loaded "+data.length+" bytes."); continue; }

                    // dumps/enc/format
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
                    if (line.equals("meta")) { System.out.print(Meta.inspectAll(data)); continue; }

                    if (line.startsWith("export ")) {
                        String[] t=line.split("\\s+"); if (t.length<3){System.out.println("export (ihex|srec) <out>"); continue;}
                        String fmt=t[1], out=t[2]; String content = switch(fmt){ case "ihex"->Exporters.intelHexExtended(data,0); case "srec"->Exporters.motorolaAuto(data,0); default->null; };
                        if (content==null){ System.out.println("Unknown format: "+fmt); continue; }
                        Files.writeString(Path.of(out), content, StandardCharsets.UTF_8); System.out.println("Wrote "+out); continue;
                    }

                    // bits
                    if (line.startsWith("getbits ")) { String[] t=line.split("\\s+"); if(t.length<3){System.out.println("getbits <bitOffset> <bitLen>"); continue;} long v=Bits.extractBits(data,Integer.parseInt(t[1]),Integer.parseInt(t[2])); System.out.println("0x"+Long.toHexString(v).toUpperCase(Locale.ROOT)+" ("+v+")"); continue; }
                    if (line.startsWith("setbits ")) { String[] t=line.split("\\s+"); if(t.length<4){System.out.println("setbits <bitOffset> <bitLen> <value>"); continue;} long val=parseNum(t[3]); Bits.insertBits(data,Integer.parseInt(t[1]),Integer.parseInt(t[2]),val); System.out.println("OK."); continue; }

                    // crypto
                    if (line.equals("crypto list")) { HybridCrypto.listProviders(); continue; }
                    if (line.startsWith("crypto use ")) { HybridCrypto.use(line.substring(11).trim()); continue; }
                    if (line.startsWith("hash ")) { System.out.println(HybridCrypto.hash(line.substring(5).trim(), data)); continue; }
                    if (line.startsWith("sign ")) { String[] t=line.split("\\s+"); if(t.length<2){System.out.println("sign <private_pkcs8.pem> [sig.bin]"); continue;} byte[] sig=HybridCrypto.sign(data, Path.of(t[1]).toFile()); if (t.length>=3) Files.write(Path.of(t[2]), sig); System.out.println(Base64.getEncoder().encodeToString(sig)); continue; }
                    if (line.startsWith("verify ")) { String[] t=line.split("\\s+"); if(t.length<3){System.out.println("verify <sig.bin> <public.pem>"); continue;} boolean ok=HybridCrypto.verify(data, Path.of(t[1]).toFile(), Path.of(t[2]).toFile()); System.out.println(ok?"OK":"FAIL"); continue; }
                    if (line.startsWith("encrypt ")) { String[] t=line.split("\\s+"); if(t.length<4){System.out.println("encrypt aesgcm <key.bin> <iv.bin> [out]"); continue;} byte[] out=HybridCrypto.encrypt(t[1], data, t[2], t[3]); String outFile=t.length>=5?t[4]:"out.enc"; Files.write(Path.of(outFile), out); System.out.println("Encrypted -> "+outFile); continue; }
                    if (line.startsWith("decrypt ")) { String[] t=line.split("\\s+"); if(t.length<4){System.out.println("decrypt aesgcm <key.bin> <iv.bin> [out]"); continue;} byte[] out=HybridCrypto.decrypt(t[1], data, t[2], t[3]); String outFile=t.length>=5?t[4]:"out.dec"; Files.write(Path.of(outFile), out); System.out.println("Decrypted -> "+outFile); continue; }

                    // settings
                    if (line.startsWith("bpl ")) { bpl = Integer.parseInt(line.split("\\s+")[1]); System.out.println("bpl="+bpl); continue; }
                    if (line.startsWith("color ")) { color = line.toLowerCase(Locale.ROOT).contains("on"); System.out.println("color="+color); continue; }

                    System.out.println("Unknown. Type 'help'.");
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
            System.out.println("Bye.");
        }

        void help() {
            System.out.println(String.join("\n",
              "Commands:",
              "  read <file>",
              "  dump | bin | oct | dec           (bpl 32 default)",
              "  json | yaml | csv | tsv | md | html",
              "  b64 | b32",
              "  detect | pcap-index | meta",
              "  export ihex <file> | export srec <file>",
              "  getbits <bitOffset> <bitLen> ; setbits <bitOffset> <bitLen> <value>",
              "  crypto list | crypto use <name>",
              "  hash <sha256|sha1|md5|blake3|argon2id|ed25519-digest>",
              "  sign <private_pkcs8.pem> [sig.bin] ; verify <sig.bin> <public.pem>",
              "  encrypt aesgcm <key.bin> <iv.bin> [out] ; decrypt aesgcm <key.bin> <iv.bin> [out]",
              "  bpl <n> ; color on|off ; quit"
            ));
        }

        long parseNum(String s) {
            s = s.trim().toLowerCase(Locale.ROOT);
            if (s.startsWith("0x")) return Long.parseLong(s.substring(2), 16);
            if (s.startsWith("0b")) return Long.parseLong(s.substring(2), 2);
            return Long.parseLong(s, 10);
        }
    }

    /* ===================== Dumps (Matrix color-ready) ===================== */

    static class Dump {
        static String hexDump(Context ctx, int offset, int bpl, boolean ascii) {
            StringBuilder sb = new StringBuilder(); byte[] d=ctx.data; boolean color=ctx.color;
            for (int i=0;i<d.length;i+=bpl) {
                int len=Math.min(bpl,d.length-i);
                sb.append(Ansi.apply(color, Ansi.DIM, String.format("%08X", i+offset))).append("  ");
                for (int j=0;j<bpl;j++) {
                    if (j<len) sb.append(Ansi.apply(color, Ansi.GREEN, String.format("%02X", d[i+j]&0xFF)));
                    else sb.append("  ");
                    if ((j&1)==1) sb.append(' ');
                }
                if (ascii) {
                    sb.append(" |");
                    for (int j=0;j<len;j++) {
                        int v=d[i+j]&0xFF; char c=(v>=0x20&&v<=0x7E)?(char)v:'.';
                        sb.append(Ansi.apply(color, Ansi.BRIGHT, String.valueOf(c)));
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
            for (int i=0;i<d.length;i+=bpl) {
                int len=Math.min(bpl,d.length-i);
                for(int j=0;j<len;j++){
                    byte v=d[i+j]; sb.append(String.format("%08X  ", i+j+offset));
                    for(int bit=7;bit>=0;bit--){ int z=(v>>bit)&1; sb.append(Ansi.apply(color, z==1?Ansi.BRIGHT:Ansi.GREEN, " "+z)); }
                    sb.append('\n');
                }
            }
            return sb.toString();
        }
        static String octalGrid(Context ctx,int offset,int bpl){
            StringBuilder sb=new StringBuilder(); boolean color=ctx.color; byte[] d=ctx.data; sb.append("Offset    Octets (base 8)\n");
            for(int i=0;i<d.length;i+=bpl){ int len=Math.min(bpl,d.length-i); sb.append(String.format("%08X  ",i+offset));
                for(int j=0;j<len;j++){ sb.append(Ansi.apply(color, Ansi.GREEN, String.format("%03o", d[i+j]&0xFF))); if(j!=len-1) sb.append(' '); }
                sb.append('\n'); }
            return sb.toString();
        }
        static String decimalGrid(Context ctx,int offset,int bpl){
            StringBuilder sb=new StringBuilder(); boolean color=ctx.color; byte[] d=ctx.data; sb.append("Offset    Octets (base 10)\n");
            for(int i=0;i<d.length;i+=bpl){ int len=Math.min(bpl,d.length-i); sb.append(String.format("%08X  ",i+offset));
                for(int j=0;j<len;j++){ sb.append(Ansi.apply(color, Ansi.GREEN, String.format("%3d", d[i+j]&0xFF))); if(j!=len-1) sb.append(' '); }
                sb.append('\n'); }
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
        private static String toBinary8(int v){ String s=Integer.toBinaryString(v&0xFF); if(s.length()<8) s="0".repeat(8-s.length())+s; return s; }
    }

    /* ============================ Encoding ============================ */

    static class Encoding {
        static String base64(byte[] data){ return Base64.getEncoder().encodeToString(data); }
        private static final char[] B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        static String base32(byte[] bytes){
            StringBuilder out=new StringBuilder((bytes.length*8+4)/5); int i=0,index=0,curr,next;
            while(i<bytes.length){ curr=bytes[i]<0?bytes[i]+256:bytes[i]; int digit;
                if(index>3){ next=(i+1<bytes.length)?(bytes[i+1]<0?bytes[i+1]+256:bytes[i+1]):0; digit=curr&(0xFF>>index); index=(index+5)%8; digit<<=index; digit|=next>>(8-index); i++; }
                else { digit=(curr>>(8-(index+5)))&0x1F; index=(index+5)%8; if(index==0) i++; }
                out.append(B32[digit]); }
            return out.toString();
        }
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
        static long extractBits(byte[] d,int bitOffset,int bitLength){
            if(bitLength<=0||bitLength>64) throw new IllegalArgumentException("bitLength 1..64");
            int byteIndex=bitOffset/8, intra=bitOffset%8, needed=(intra+bitLength+7)/8;
            if(byteIndex+needed>d.length) throw new IllegalArgumentException("range exceeds length");
            long acc=0; for(int i=0;i<needed;i++) acc=(acc<<8)|(d[byteIndex+i]&0xFFL);
            int shift=(needed*8)-intra-bitLength; return (acc>>>shift) & ((bitLength==64)?-1L:((1L<<bitLength)-1L));
        }
        static void insertBits(byte[] d,int bitOffset,int bitLength,long value){
            if(bitLength<=0||bitLength>64) throw new IllegalArgumentException("bitLength 1..64");
            int byteIndex=bitOffset/8, intra=bitOffset%8, needed=(intra+bitLength+7)/8;
            if(byteIndex+needed>d.length) throw new IllegalArgumentException("range exceeds length");
            long mask=(bitLength==64)?-1L:((1L<<bitLength)-1L); long cur=0; for(int i=0;i<needed;i++) cur=(cur<<8)|(d[byteIndex+i]&0xFFL);
            int shift=(needed*8)-intra-bitLength; long cleared=cur & ~(mask<<shift); long with=cleared|((value&mask)<<shift);
            for(int i=needed-1;i>=0;i--){ d[byteIndex+i]=(byte)(with&0xFF); with>>>=8; }
        }
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
                for(int j=0;j<len;j++){ int b=data[i+j]&0xFF; sb.append(String.format("%02X",b)); sum=(sum+b)&0FF; }
                int cks=(~sum)&0xFF; sb.append(String.format("%02X",cks)).append('\n'); }
            return switch(type){ case 1->sb.append("S9030000FC\n").toString(); case 2->sb.append("S804000000FB\n").toString(); default->sb.append("S70500000000FA\n").toString(); };
        }
    }

    /* ============================ Sniffers / PCAP Index ============================ */

    static class Sniff {
        static String detectAll(byte[] b){
            StringBuilder sb=new StringBuilder("== Sniff Results ==\n"); boolean any=false; String s;
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
        static String mp3(byte[] b){
            StringBuilder sb=new StringBuilder();
            if (b.length>=10 && b[0]=='I'&&b[1]=='D'&&b[2]=='3') {
                int size = synchsafeToInt(b[6],b[7],b[8],b[9]);
                sb.append("MP3: ID3v2, size=").append(size).append("\n");
                int pos = 10; int end = Math.min(b.length, 10+size);
                while (pos+10<=end) {
                    String id = new String(b, pos, 4, StandardCharsets.ISO_8859_1);
                    if (!id.matches("[A-Z0-9]{4}")) break;
                    int frameSize = ((b[pos+4]&0xFF)<<24)|((b[pos+5]&0xFF)<<16)|((b[pos+6]&0xFF)<<8)|(b[pos+7]&0xFF);
                    if (frameSize<=0 || pos+10+frameSize> end) break;
                    if (frameSize<=512) {
                        byte enc = b[pos+10];
                        String val = decodeId3(enc, b, pos+11, frameSize-1);
                        if (id.matches("T(IT2|PE1|ALB|CON|COP|DRC|YER)")) sb.append("  ").append(id).append(": ").append(val).append("\n");
                    }
                    pos += 10 + frameSize;
                }
            }
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
        static int synchsafeToInt(byte b0, byte b1, byte b2, byte b3) { return ((b0 & 0x7F) << 21) | ((b1 & 0x7F) << 14) | ((b2 & 0x7F) << 7) | (b3 & 0x7F); }
        static String decodeId3(byte enc, byte[] arr, int off, int len) {
            try {
                return switch (enc) {
                    case 0 -> trimNulls(new String(arr, off, len, StandardCharsets.ISO_8859_1));
                    case 1 -> trimNulls(new String(arr, off, len, "UTF-16"));
                    case 2 -> trimNulls(new String(arr, off, len, "UTF-16BE"));
                    case 3 -> trimNulls(new String(arr, off, len, StandardCharsets.UTF_8));
                    default -> trimNulls(new String(arr, off, len, StandardCharsets.ISO_8859_1));
                };
            } catch (Exception e) { return trimNulls(new String(arr, off, len, StandardCharsets.ISO_8859_1)); }
        }
        static String trimNulls(String s){ int i=s.indexOf(0); return i>=0 ? s.substring(0,i) : s.trim(); }

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

        static String jpegHeaders(byte[] b){
            if (b.length<4 || (b[0]&0xFF)!=0xFF || (b[1]&0xFF)!=0xD8) return "";
            StringBuilder sb=new StringBuilder(); int pos=2;
            while (pos+4<=b.length) {
                if ((b[pos]&0xFF)!=0xFF) break;
                int marker = b[pos+1]&0xFF; if (marker==0xDA) break; // SOS
                int len = ((b[pos+2]&0xFF)<<8)|(b[pos+3]&0xFF); if (len<2 || pos+2+len> b.length) break;
                if (marker==0xE1) {
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

    /* ============================ Crypto (Hybrid facade) ============================ */

    static class HybridCrypto {
        static String current = "builtin";
        static CryptoPluginsMatrixHybrid.CryptoPlugin plugin = CryptoPluginsMatrixHybrid.get("builtin");

        static void listProviders() {
            System.out.println("== Crypto Providers ==");
            for (String k : CryptoPluginsMatrixHybrid.keys()) {
                var p = CryptoPluginsMatrixHybrid.get(k);
                System.out.println(" - " + k + (k.equals(current) ? "  [ACTIVE]" : "") + (p.simulated() ? "  (SIMULATED)" : ""));
            }
            System.out.println("-- Installed JCE providers --");
            for (Provider p : Security.getProviders()) System.out.println("  * " + p.getName() + " " + p.getVersionStr());
            System.out.println("-- Plugin dir --");
            System.out.println("  " + CryptoPluginsMatrixHybrid.PLUGIN_DIR.toString());
        }

        static void use(String name) {
            var p = CryptoPluginsMatrixHybrid.get(name);
            if (p == null) throw new IllegalArgumentException("No such provider: " + name);
            plugin = p; current = name;
            System.out.println("[Matrix+] Using provider: " + name + (p.simulated() ? " (SIMULATED)" : ""));
        }

        static String hash(String alg, byte[] data) throws Exception { return plugin.hash(alg, data); }
        static byte[] sign(byte[] data, File priv) throws Exception { return plugin.sign(data, priv); }
        static boolean verify(byte[] data, File sig, File pub) throws Exception { return plugin.verify(data, sig, pub); }
        static byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { return plugin.encrypt(cipher, data, keyFile, ivFile); }
        static byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { return plugin.decrypt(cipher, data, keyFile, ivFile); }
    }

    /* ============================ IO helpers ============================ */

    static byte[] loadInput(CliOptions opt) throws IOException {
        if (opt.stdin) return readAll(System.in);
        if (opt.inFile != null) return Files.readAllBytes(Path.of(opt.inFile));
        if (opt.literalString != null) return opt.literalString.getBytes(StandardCharsets.UTF_8);
        return null;
    }
    static byte[] readAll(InputStream in) throws IOException { ByteArrayOutputStream bos = new ByteArrayOutputStream(); byte[] buf=new byte[8192]; int r; while((r=in.read(buf))!=-1) bos.write(buf,0,r); return bos.toByteArray(); }
}
