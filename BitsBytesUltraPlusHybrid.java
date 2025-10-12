import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BitsBytesUltraPlusHybrid (Matrix, Simulated Plugins)
 * ----------------------------------------------------
 * Dual-mode: CLI if args, REPL if none. Matrix-green vibe.
 *
 * Core features (real):
 *  - Hash: SHA-256/SHA-1/MD5
 *  - Sign/Verify: RSA SHA256 (PKCS#8 private / X.509 public)
 *  - Encrypt/Decrypt: AES/GCM/NoPadding (128/256 if policy allows)
 *
 * Hybrid crypto:
 *  - crypto list / crypto use <name>
 *  - Pluggable providers from CryptoPluginsSim
 *  - Simulated plugins (ed25519/blake3/argon2id) clearly labeled "SIMULATED"
 *
 * NOTE: This file includes a compact hexdump & Base64 & tiny metadata.
 * If you want the *full* earlier dump/format/sniffer suite, paste it in;
 * these classes coexist fine (names won’t collide).
 */
public class BitsBytesUltraPlusHybridSim {

    /* ============================ MAIN ============================ */

    public static void main(String[] args) {
        try {
            if (args.length == 0) { new Shell().run(); return; }
            CliOptions opt = CliOptions.parse(args);
            byte[] data = loadInput(opt);
            if (data == null) { System.err.println("No input. Use --in, --str, or --stdin."); System.exit(2); }

            // Init plugins
            CryptoPluginsSim.loadProviders(); // registers builtin + simulated

            // CLI actions
            if (opt.cryptoList) { HybridCrypto.list(); return; }
            if (opt.cryptoUse != null) { HybridCrypto.use(opt.cryptoUse); }

            if (opt.hashAlg != null) {
                System.out.println(HybridCrypto.hash(opt.hashAlg, data));
            }

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
                    try (FileOutputStream fos = new FileOutputStream(opt.outFile == null ? "out.enc" : opt.outFile)) { fos.write(out); }
                    System.out.println("Encrypted -> " + (opt.outFile == null ? "out.enc" : opt.outFile));
                } else if ("decrypt".equals(opt.encMode)) {
                    byte[] out = HybridCrypto.decrypt(opt.cipher, data, opt.keyFile, opt.ivFile);
                    try (FileOutputStream fos = new FileOutputStream(opt.outFile == null ? "out.dec" : opt.outFile)) { fos.write(out); }
                    System.out.println("Decrypted -> " + (opt.outFile == null ? "out.dec" : opt.outFile));
                }
            }

            if (opt.dump) System.out.print(Dump.hexDump(data, 32, true));
            if (opt.b64) System.out.println(Base64.getEncoder().encodeToString(data));
            if (opt.meta) System.out.print(Meta.quick(data));

            if (opt.nothingChosen()) System.out.print(Dump.hexDump(data, 32, true));
        } catch (Exception e) {
            System.err.println("[ERR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    /* ============================ CLI ============================ */

    static class CliOptions {
        String inFile=null, literalString=null;
        boolean stdin=false, dump=false, b64=false, meta=false;
        boolean cryptoList=false;
        String cryptoUse=null;
        String hashAlg=null;
        String signPem=null, sigOut=null, verifySig=null, verifyPub=null;
        String encMode=null, cipher=null, keyFile=null, ivFile=null, outFile=null;

        static CliOptions parse(String[] a) {
            CliOptions o = new CliOptions();
            for (int i=0;i<a.length;i++) {
                switch (a[i]) {
                    case "--in": o.inFile = need(a, ++i, "--in <file>"); break;
                    case "--str": o.literalString = need(a, ++i, "--str <text>"); break;
                    case "--stdin": o.stdin=true; break;
                    case "--dump": o.dump=true; break;
                    case "--b64": o.b64=true; break;
                    case "--meta": o.meta=true; break;

                    case "--crypto-list": o.cryptoList=true; break;
                    case "--crypto-use": o.cryptoUse = need(a, ++i, "--crypto-use <name>"); break;

                    case "--hash": o.hashAlg = need(a, ++i, "--hash <sha256|sha1|md5|blake3|argon2id|ed25519-digest>"); break;
                    case "--sign": o.signPem = need(a, ++i, "--sign <private.pem>"); break;
                    case "--sig-out": o.sigOut = need(a, ++i, "--sig-out <file>"); break;
                    case "--verify": o.verifySig = need(a, ++i, "--verify <sig.bin> <pub.pem>"); o.verifyPub = need(a, ++i, "<pub.pem>"); break;

                    case "--encrypt": o.encMode="encrypt"; o.cipher = need(a, ++i, "--encrypt <aesgcm>"); o.keyFile = need(a, ++i, "<key.bin>"); o.ivFile = need(a, ++i, "<iv.bin>"); o.outFile = (i+1<a.length && !a[i+1].startsWith("--"))? a[++i]: null; break;
                    case "--decrypt": o.encMode="decrypt"; o.cipher = need(a, ++i, "--decrypt <aesgcm>"); o.keyFile = need(a, ++i, "<key.bin>"); o.ivFile = need(a, ++i, "<iv.bin>"); o.outFile = (i+1<a.length && !a[i+1].startsWith("--"))? a[++i]: null; break;

                    case "--help": case "-h": throw new IllegalArgumentException(usage());
                    default: throw new IllegalArgumentException("Unknown: "+a[i]+"\n\n"+usage());
                }
            }
            return o;
        }
        boolean nothingChosen() {
            return !(dump||b64||meta||cryptoList||cryptoUse!=null||hashAlg!=null||signPem!=null||verifySig!=null||encMode!=null);
        }
        static String need(String[] a,int i,String msg){ if(i>=a.length) throw new IllegalArgumentException(msg); return a[i]; }
        static String usage(){
            return String.join("\n",
              "BitsBytesUltraPlusHybridSim - Matrix Hybrid (simulated plugins)",
              "Usage:",
              "  java BitsBytesUltraPlusHybridSim (--in <file> | --str <text> | --stdin) [opts]",
              "",
              "Options:",
              "  --dump                   Hexdump (32 B/line)",
              "  --b64                    Print Base64",
              "  --meta                   Quick metadata (MP3/PNG/JPEG/PDF-lite)",
              "",
              "Crypto (built-in real):",
              "  --hash <sha256|sha1|md5>",
              "  --sign <private_pkcs8.pem> [--sig-out sig.bin]",
              "  --verify <sig.bin> <public.pem>",
              "  --encrypt aesgcm <key.bin> <iv.bin> [out.enc]",
              "  --decrypt aesgcm <key.bin> <iv.bin> [out.dec]",
              "",
              "Hybrid plugins:",
              "  --crypto-list            List providers (builtin + plugins)",
              "  --crypto-use <name>      Select provider (builtin|ed25519|blake3|argon2id)",
              "  (Simulated plugins clearly labeled; not for production security)"
            );
        }
    }

    /* ======================== IO / Helpers ======================== */

    static byte[] loadInput(CliOptions opt) throws IOException {
        if (opt.stdin) return readAll(System.in);
        if (opt.inFile != null) return Files.readAllBytes(new File(opt.inFile).toPath());
        if (opt.literalString != null) return opt.literalString.getBytes(StandardCharsets.UTF_8);
        return null;
    }
    static byte[] readAll(InputStream in) throws IOException { ByteArrayOutputStream bos = new ByteArrayOutputStream(); byte[] buf=new byte[8192]; int r; while((r=in.read(buf))!=-1) bos.write(buf,0,r); return bos.toByteArray(); }

    /* ======================== Hybrid Crypto Facade ======================== */

    static class HybridCrypto {
        static String current = "builtin";
        static CryptoPluginsSim.CryptoPlugin plugin = CryptoPluginsSim.get("builtin");

        static void list() {
            System.out.println("== Crypto Providers ==");
            for (String k : CryptoPluginsSim.keys()) {
                CryptoPluginsSim.CryptoPlugin p = CryptoPluginsSim.get(k);
                System.out.println(" - " + k + (k.equals(current) ? "  [ACTIVE]" : "") + (p.simulated() ? "  (SIMULATED)" : ""));
            }
        }
        static void use(String name) {
            CryptoPluginsSim.CryptoPlugin p = CryptoPluginsSim.get(name);
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

    /* ============================= Shell ============================= */

    static class Shell {
        final Scanner sc = new Scanner(System.in);
        byte[] data = new byte[0];

        void run() {
            System.out.println("BitsBytesUltraPlusHybridSim (Matrix). Type 'help'.");
            while (true) {
                System.out.print("Matrix> ");
                if (!sc.hasNextLine()) break;
                String line = sc.nextLine().trim();
                if (line.isEmpty()) continue;
                try {
                    if (line.equals("quit")||line.equals("exit")) break;
                    if (line.equals("help")) { help(); continue; }
                    if (line.startsWith("read ")) { data = Files.readAllBytes(new File(line.substring(5).trim()).toPath()); System.out.println("Loaded "+data.length+" bytes"); continue; }
                    if (line.equals("dump")) { System.out.print(Dump.hexDump(data, 32, true)); continue; }
                    if (line.equals("b64")) { System.out.println(Base64.getEncoder().encodeToString(data)); continue; }
                    if (line.equals("meta")) { System.out.print(Meta.quick(data)); continue; }

                    if (line.equals("crypto list")) { HybridCrypto.list(); continue; }
                    if (line.startsWith("crypto use ")) { HybridCrypto.use(line.substring(11).trim()); continue; }

                    if (line.startsWith("hash ")) { System.out.println(HybridCrypto.hash(line.substring(5).trim(), data)); continue; }
                    if (line.startsWith("sign ")) { String pk = line.substring(5).trim(); byte[] sig = HybridCrypto.sign(data, new File(pk)); System.out.println(Base64.getEncoder().encodeToString(sig)); continue; }
                    if (line.startsWith("verify ")) { String[] t=line.split("\\s+"); if (t.length<3){System.out.println("Usage: verify <sig.bin> <pub.pem>"); continue;} boolean ok=HybridCrypto.verify(data,new File(t[1]),new File(t[2])); System.out.println(ok?"OK":"FAIL"); continue; }

                    if (line.startsWith("encrypt ")) { String[] t=line.split("\\s+"); if (t.length<4){System.out.println("encrypt aesgcm <key.bin> <iv.bin> [out]"); continue;} byte[] out=HybridCrypto.encrypt(t[1], data, t[2], t[3]); String outFile=t.length>=5?t[4]:"out.enc"; try(FileOutputStream fos=new FileOutputStream(outFile)){ fos.write(out);} System.out.println("Encrypted -> "+outFile); continue; }
                    if (line.startsWith("decrypt ")) { String[] t=line.split("\\s+"); if (t.length<4){System.out.println("decrypt aesgcm <key.bin> <iv.bin> [out]"); continue;} byte[] out=HybridCrypto.decrypt(t[1], data, t[2], t[3]); String outFile=t.length>=5?t[4]:"out.dec"; try(FileOutputStream fos=new FileOutputStream(outFile)){ fos.write(out);} System.out.println("Decrypted -> "+outFile); continue; }

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
              "  read <file>                  Load bytes",
              "  dump | b64 | meta            Hexdump / Base64 / quick metadata",
              "  crypto list | crypto use <name>",
              "  hash <sha256|sha1|md5|blake3|argon2id|ed25519-digest>",
              "  sign <private_pkcs8.pem>    (RSA-SHA256 for builtin; SIM for ed25519)",
              "  verify <sig.bin> <pub.pem>",
              "  encrypt aesgcm <key.bin> <iv.bin> [out]",
              "  decrypt aesgcm <key.bin> <iv.bin> [out]",
              "  quit"
            ));
        }
    }

    /* ====================== Minimal Hexdump & Meta ====================== */

    static class Dump {
        static String hexDump(byte[] d, int bpl, boolean ascii) {
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<d.length;i+=bpl) {
                int len = Math.min(bpl, d.length-i);
                sb.append(String.format("%08X  ", i));
                for (int j=0;j<bpl;j++) {
                    if (j<len) sb.append(String.format("%02X", d[i+j] & 0xFF));
                    else sb.append("  ");
                    if ((j&1)==1) sb.append(' ');
                }
                if (ascii) {
                    sb.append(" |");
                    for (int j=0;j<len;j++) {
                        int v=d[i+j]&0xFF; char c=(v>=0x20&&v<=0x7E)?(char)v:'.'; sb.append(c);
                    }
                    sb.append('|');
                }
                sb.append('\n');
            }
            return sb.toString();
        }
    }
    static class Meta {
        static String quick(byte[] b){
            StringBuilder sb=new StringBuilder("== Meta Quick ==\n");
            if (b.length>=3 && b[0]=='I'&&b[1]=='D'&&b[2]=='3') sb.append("MP3: ID3v2 present\n");
            if (b.length>=128 && b[b.length-128]=='T'&&b[b.length-127]=='A'&&b[b.length-126]=='G') sb.append("MP3: ID3v1 present\n");
            if (b.length>=8 && (b[0]&0xFF)==0x89 && b[1]=='P' && b[2]=='N' && b[3]=='G') sb.append("PNG: signature OK\n");
            if (b.length>=4 && b[0]==(byte)0xFF && b[1]==(byte)0xD8) sb.append("JPEG: SOI\n");
            if (new String(b,0,Math.min(4096,b.length), StandardCharsets.ISO_8859_1).contains("%PDF")) sb.append("PDF: header\n");
            return sb.toString();
        }
    }

    /* =========================== CryptoPlugins hook =========================== */

    // Facade uses CryptoPluginsSim; nothing else needed here.
}
