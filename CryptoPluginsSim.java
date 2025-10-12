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
 * CryptoPluginsSim — plugin registry (SIMULATED edition)
 * -----------------------------------------------------
 * Provides:
 *  - builtin (real): SHA-*, RSA-SHA256, AES-GCM
 *  - ed25519 (SIM): fake signature via HMAC-like SHA-256 with key bytes
 *  - blake3  (SIM): maps to SHA-256 with label
 *  - argon2id (SIM): maps to PBKDF2WithHmacSHA256 digest
 *
 * All SIMULATED providers are clearly flagged. For real security, use the STRICT build
 * or add a real JCE provider (e.g., BouncyCastle) and use the STRICT plugins.
 */
public class CryptoPluginsSim {

    /* ======================= Registry ======================= */

    public interface CryptoPlugin {
        String name();
        boolean simulated(); // true if not cryptographically real
        String hash(String alg, byte[] data) throws Exception;
        byte[] sign(byte[] data, File privateKey) throws Exception;     // signature bytes
        boolean verify(byte[] data, File sigFile, File publicKey) throws Exception;
        byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception;
        byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception;
    }

    private static final Map<String,CryptoPlugin> REG = new LinkedHashMap<>();

    public static void loadProviders() {
        // Always present
        register(new BuiltinPlugin());
        // Simulated extras
        register(new Ed25519SimPlugin());
        register(new Blake3SimPlugin());
        register(new Argon2idSimPlugin());
    }

    public static void register(CryptoPlugin p){ REG.put(p.name(), p); }
    public static Set<String> keys(){ return REG.keySet(); }
    public static CryptoPlugin get(String k){ return REG.get(k); }

    /* ======================= Helpers ======================= */

    static byte[] readAll(File f) throws IOException { return Files.readAllBytes(f.toPath()); }
    static byte[] readKey(File f) throws IOException { return readAll(f); }
    static byte[] readIv(File f) throws IOException { return readAll(f); }
    static byte[] fromBase64IfAscii(byte[] b){
        String s = new String(b, StandardCharsets.US_ASCII).trim();
        if (s.matches("[A-Za-z0-9+/=\\s]+")) {
            try { return Base64.getMimeDecoder().decode(s); } catch (Exception ignored) {}
        }
        return b;
    }
    static String hex(byte[] x){ StringBuilder sb=new StringBuilder(x.length*2); for(byte b:x) sb.append(String.format("%02x",b&0xFF)); return sb.toString(); }

    /* ======================= Builtin (REAL) ======================= */

    static class BuiltinPlugin implements CryptoPlugin {
        public String name(){ return "builtin"; }
        public boolean simulated(){ return false; }

        public String hash(String alg, byte[] data) throws Exception {
            String j = switch (alg.toLowerCase(Locale.ROOT)) {
                case "sha256" -> "SHA-256";
                case "sha1" -> "SHA-1";
                case "md5" -> "MD5";
                // allow passthrough names from sim variants too, as aliases:
                case "blake3","argon2id","ed25519-digest" -> "SHA-256";
                default -> throw new GeneralSecurityException("Unknown hash: "+alg);
            };
            MessageDigest md = MessageDigest.getInstance(j);
            byte[] dig = md.digest(data);
            return alg.toUpperCase(Locale.ROOT) + " (via " + j + "):\nHEX  " + hex(dig) + "\nB64  " + Base64.getEncoder().encodeToString(dig) + "\n";
        }

        public byte[] sign(byte[] data, File privateKey) throws Exception {
            // RSA SHA256 (PKCS#8)
            String p = Files.readString(privateKey.toPath(), StandardCharsets.US_ASCII);
            String base = extractPem(p, "PRIVATE KEY");
            byte[] der = Base64.getMimeDecoder().decode(base);
            PrivateKey pk = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(pk); s.update(data); return s.sign();
        }

        public boolean verify(byte[] data, File sigFile, File publicKey) throws Exception {
            byte[] sig = fromBase64IfAscii(readAll(sigFile));
            String p = Files.readString(publicKey.toPath(), StandardCharsets.US_ASCII);
            String base = extractPem(p, "PUBLIC KEY");
            byte[] der = Base64.getMimeDecoder().decode(base);
            PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(pub); s.update(data); return s.verify(sig);
        }

        public byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception {
            if (!"aesgcm".equalsIgnoreCase(cipher)) throw new GeneralSecurityException("Only aesgcm supported here");
            byte[] key = readKey(new File(keyFile));
            byte[] iv  = readIv(new File(ivFile));
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, ks, new GCMParameterSpec(128, iv));
            return c.doFinal(data);
        }

        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception {
            if (!"aesgcm".equalsIgnoreCase(cipher)) throw new GeneralSecurityException("Only aesgcm supported here");
            byte[] key = readKey(new File(keyFile));
            byte[] iv  = readIv(new File(ivFile));
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, ks, new GCMParameterSpec(128, iv));
            return c.doFinal(data);
        }

        private static String extractPem(String pem, String type) throws GeneralSecurityException {
            String start = "-----BEGIN " + type + "-----";
            String end   = "-----END " + type + "-----";
            int s = pem.indexOf(start), e = pem.indexOf(end);
            if (s<0 || e<0) throw new GeneralSecurityException(type+" PEM not found");
            return pem.substring(s + start.length(), e).replaceAll("\\s", "");
        }
    }

    /* ======================= Simulated Plugins ======================= */

    static class Ed25519SimPlugin implements CryptoPlugin {
        public String name(){ return "ed25519"; }
        public boolean simulated(){ return true; }

        public String hash(String alg, byte[] data) throws Exception {
            // “ed25519-digest” = SHA-256(data) with label notice
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(data);
            return "ED25519-DIGEST (SIM via SHA-256):\nHEX  " + hex(dig) + "\nB64  " + Base64.getEncoder().encodeToString(dig) + "\n";
        }

        public byte[] sign(byte[] data, File privateKey) throws Exception {
            // SIMULATION: signature = SHA-256( "SIM-ED25519" || key || data )
            byte[] k = readAll(privateKey);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("SIM-ED25519".getBytes(StandardCharsets.US_ASCII));
            md.update(k);
            md.update(data);
            return md.digest();
        }

        public boolean verify(byte[] data, File sigFile, File publicKey) throws Exception {
            // SIMULATION: recompute with public key bytes (not secure—demo only)
            byte[] k = readAll(publicKey);
            byte[] sig = fromBase64IfAscii(readAll(sigFile));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("SIM-ED25519".getBytes(StandardCharsets.US_ASCII));
            md.update(k);
            md.update(data);
            return MessageDigest.isEqual(md.digest(), sig);
        }

        public byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception {
            throw new GeneralSecurityException("ed25519 plugin does not support encryption (SIM)");
        }

        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception {
            throw new GeneralSecurityException("ed25519 plugin does not support encryption (SIM)");
        }
    }

    static class Blake3SimPlugin implements CryptoPlugin {
        public String name(){ return "blake3"; }
        public boolean simulated(){ return true; }

        public String hash(String alg, byte[] data) throws Exception {
            // SIM: SHA-256("SIM-BLAKE3"||data)
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("SIM-BLAKE3".getBytes(StandardCharsets.US_ASCII));
            byte[] dig = md.digest(data);
            return "BLAKE3 (SIM via SHA-256):\nHEX  " + hex(dig) + "\nB64  " + Base64.getEncoder().encodeToString(dig) + "\n";
        }
        public byte[] sign(byte[] data, File privateKey) throws Exception { throw new GeneralSecurityException("blake3 plugin: sign not supported (SIM)"); }
        public boolean verify(byte[] data, File sigFile, File publicKey) throws Exception { throw new GeneralSecurityException("blake3 plugin: verify not supported (SIM)"); }
        public byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("blake3 plugin: encrypt not supported (SIM)"); }
        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("blake3 plugin: decrypt not supported (SIM)"); }
    }

    static class Argon2idSimPlugin implements CryptoPlugin {
        public String name(){ return "argon2id"; }
        public boolean simulated(){ return true; }

        public String hash(String alg, byte[] data) throws Exception {
            // SIM: PBKDF2WithHmacSHA256(data, salt="SIM-ARGON2ID", 10k) then print digest
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                    toChars(data), "SIM-ARGON2ID".getBytes(StandardCharsets.US_ASCII), 10_000, 256);
            byte[] dk = skf.generateSecret(spec).getEncoded();
            return "ARGON2ID (SIM via PBKDF2-SHA256 x10k):\nHEX  " + hex(dk) + "\nB64  " + Base64.getEncoder().encodeToString(dk) + "\n";
        }
        static char[] toChars(byte[] b){ char[] c=new char[b.length]; for(int i=0;i<b.length;i++) c[i]=(char)(b[i]&0xFF); return c; }

        public byte[] sign(byte[] data, File privateKey) throws Exception { throw new GeneralSecurityException("argon2id: sign N/A (SIM)"); }
        public boolean verify(byte[] data, File sigFile, File publicKey) throws Exception { throw new GeneralSecurityException("argon2id: verify N/A (SIM)"); }
        public byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("argon2id: encrypt N/A (SIM)"); }
        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("argon2id: decrypt N/A (SIM)"); }
    }
}
