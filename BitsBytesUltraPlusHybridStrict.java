import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BitsBytesUltraPlusHybrid (Matrix, STRICT Plugins)
 * ------------------------------------------------
 * Same UX as Sim version, but NO simulations. Extra algos only work if
 * a real JCE provider (e.g., BouncyCastle) is on the classpath.
 *
 * Real built-ins: SHA-256/SHA-1/MD5, RSA-SHA256 sign/verify, AES-GCM.
 * Strict plugins will throw "Unavailable" unless provider present.
 */
public class BitsBytesUltraPlusHybridStrict {

    public static void main(String[] args) {
        try {
            if (args.length == 0) { new Shell().run(); return; }
            CliOptions opt = CliOptions.parse(args);
            byte[] data = loadInput(opt);
            if (data == null) { System.err.println("No input. Use --in, --str, or --stdin."); System.exit(2); }

            CryptoPluginsStrict.loadProviders(); // builtin + STRICT plugins

            if (opt.cryptoList) { HybridCrypto.list(); return; }
            if (opt.cryptoUse != null) { HybridCrypto.use(opt.cryptoUse); }

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

            if (opt.nothingChosen()) System.out.print(Dump.hexDump(data, 32, true));
        } catch (Exception e) {
            System.err.println("[ERR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    /* ---------------- CLI & Helpers (same as Sim, trimmed) ---------------- */

    static class CliOptions {
        String inFile=null, literalString=null;
        boolean stdin=false, dump=false, b64=false;
        boolean cryptoList=false; String cryptoUse=null;
        String hashAlg=null; String signPem=null, sigOut=null, verifySig=null, verifyPub=null;
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
        boolean nothingChosen(){ return !(dump||b64||cryptoList||cryptoUse!=null||hashAlg!=null||signPem!=null||verifySig!=null||encMode!=null); }
        static String need(String[] a,int i,String msg){ if(i>=a.length) throw new IllegalArgumentException(msg); return a[i]; }
        static String usage(){ return "BitsBytesUltraPlusHybridStrict - use --crypto-list for providers"; }
    }

    static byte[] loadInput(CliOptions opt) throws IOException {
        if (opt.stdin) return readAll(System.in);
        if (opt.inFile != null) return Files.readAllBytes(new File(opt.inFile).toPath());
        if (opt.literalString != null) return opt.literalString.getBytes(StandardCharsets.UTF_8);
        return null;
    }
    static byte[] readAll(InputStream in) throws IOException { ByteArrayOutputStream bos = new ByteArrayOutputStream(); byte[] buf=new byte[8192]; int r; while((r=in.read(buf))!=-1) bos.write(buf,0,r); return bos.toByteArray(); }

    /* ---------------- Hybrid Crypto Facade (uses STRICT plugins) ---------------- */

    static class HybridCrypto {
        static String current = "builtin";
        static CryptoPluginsStrict.CryptoPlugin plugin = CryptoPluginsStrict.get("builtin");

        static void list() {
            System.out.println("== Crypto Providers ==");
            for (String k : CryptoPluginsStrict.keys()) {
                CryptoPluginsStrict.CryptoPlugin p = CryptoPluginsStrict.get(k);
                System.out.println(" - " + k + (k.equals(current) ? "  [ACTIVE]" : ""));
            }
            // Also show installed JCE providers:
            System.out.println("-- JCE providers installed --");
            for (Provider p : Security.getProviders()) System.out.println("  * " + p.getName() + " " + p.getVersionStr());
        }

        static void use(String name) {
            CryptoPluginsStrict.CryptoPlugin p = CryptoPluginsStrict.get(name);
            if (p == null) throw new IllegalArgumentException("No such provider: " + name);
            plugin = p; current = name;
            System.out.println("[Matrix+] Using provider: " + name);
        }

        static String hash(String alg, byte[] data) throws Exception { return plugin.hash(alg, data); }
        static byte[] sign(byte[] data, File priv) throws Exception { return plugin.sign(data, priv); }
        static boolean verify(byte[] data, File sig, File pub) throws Exception { return plugin.verify(data, sig, pub); }
        static byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { return plugin.encrypt(cipher, data, keyFile, ivFile); }
        static byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { return plugin.decrypt(cipher, data, keyFile, ivFile); }
    }

    /* ---------------- Mini hexdump (for convenience) ---------------- */

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
}
