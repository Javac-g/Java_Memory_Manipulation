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
 * CryptoPluginsStrict — REAL-ONLY plugins.
 * ---------------------------------------
 * - builtin: real SHA-*, RSA-SHA256, AES-GCM (always available)
 * - ed25519: requires Signature.getInstance("Ed25519") from a provider (e.g., BC)
 * - blake3 : requires MessageDigest "BLAKE3-256" (BC)
 * - argon2id: requires SecretKeyFactory "Argon2id" (BC or other)
 *
 * If algorithms are missing, these plugins THROW clear errors.
 */
public class CryptoPluginsStrict {

    public interface CryptoPlugin {
        String name();
        String hash(String alg, byte[] data) throws Exception;
        byte[] sign(byte[] data, File privateKey) throws Exception;
        boolean verify(byte[] data, File sigFile, File publicKey) throws Exception;
        byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception;
        byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception;
    }

    private static final Map<String,CryptoPlugin> REG = new LinkedHashMap<>();

    public static void loadProviders() {
        register(new BuiltinPlugin());
        register(new Ed25519Plugin());
        register(new Blake3Plugin());
        register(new Argon2idPlugin());
    }

    public static void register(CryptoPlugin p){ REG.put(p.name(), p); }
    public static Set<String> keys(){ return REG.keySet(); }
    public static CryptoPlugin get(String k){ return REG.get(k); }

    /* ---------------- Helpers ---------------- */

    static byte[] readAll(File f) throws IOException { return Files.readAllBytes(f.toPath()); }
    static byte[] fromBase64IfAscii(byte[] b){
        String s = new String(b, StandardCharsets.US_ASCII).trim();
        if (s.matches("[A-Za-z0-9+/=\\s]+")) {
            try { return Base64.getMimeDecoder().decode(s); } catch (Exception ignored) {}
        }
        return b;
    }
    static String hex(byte[] x){ StringBuilder sb=new StringBuilder(x.length*2); for(byte b:x) sb.append(String.format("%02x",b&0xFF)); return sb.toString(); }

    static String extractPem(String pem, String type) throws GeneralSecurityException {
        String start = "-----BEGIN " + type + "-----";
        String end   = "-----END " + type + "-----";
        int s = pem.indexOf(start), e = pem.indexOf(end);
        if (s<0 || e<0) throw new GeneralSecurityException(type+" PEM not found");
        return pem.substring(s + start.length(), e).replaceAll("\\s", "");
    }

    /* ---------------- Builtin (REAL) ---------------- */

    static class BuiltinPlugin implements CryptoPlugin {
        public String name(){ return "builtin"; }

        public String hash(String alg, byte[] data) throws Exception {
            String j = switch (alg.toLowerCase(Locale.ROOT)) {
                case "sha256" -> "SHA-256";
                case "sha1" -> "SHA-1";
                case "md5" -> "MD5";
                default -> throw new GeneralSecurityException("Unknown hash: "+alg);
            };
            MessageDigest md = MessageDigest.getInstance(j);
            byte[] dig = md.digest(data);
            return alg.toUpperCase(Locale.ROOT) + ":\nHEX  " + hex(dig) + "\nB64  " + Base64.getEncoder().encodeToString(dig) + "\n";
        }

        public byte[] sign(byte[] data, File privateKey) throws Exception {
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
            byte[] key = readAll(new File(keyFile));
            byte[] iv  = readAll(new File(ivFile));
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, ks, new GCMParameterSpec(128, iv));
            return c.doFinal(data);
        }

        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception {
            if (!"aesgcm".equalsIgnoreCase(cipher)) throw new GeneralSecurityException("Only aesgcm supported here");
            byte[] key = readAll(new File(keyFile));
            byte[] iv  = readAll(new File(ivFile));
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, ks, new GCMParameterSpec(128, iv));
            return c.doFinal(data);
        }
    }

    /* ---------------- Strict Plugins (require provider) ---------------- */

    static class Ed25519Plugin implements CryptoPlugin {
        public String name(){ return "ed25519"; }

        public String hash(String alg, byte[] data) throws Exception {
            // Ed25519 has no hash primitive; allow "ed25519-digest" only if provider offers "Ed25519" + "SHA-256" for printing
            if (!isAlgAvailable("Signature", "Ed25519")) throw new GeneralSecurityException("Ed25519 unavailable (install a provider)");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data);
            return "ED25519 digest helper (SHA-256):\nHEX  " + hex(d) + "\nB64  " + Base64.getEncoder().encodeToString(d) + "\n";
        }

        public byte[] sign(byte[] data, File privateKey) throws Exception {
            if (!isAlgAvailable("Signature", "Ed25519")) throw new GeneralSecurityException("Ed25519 unavailable (install a provider)");
            String p = Files.readString(privateKey.toPath(), StandardCharsets.US_ASCII);
            // Accept either PKCS#8 PRIVATE KEY (Ed25519) or OpenSSH private key if provider supports reading.
            String base = extractPem(p, "PRIVATE KEY");
            byte[] der = Base64.getMimeDecoder().decode(base);
            PrivateKey pk;
            try { pk = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der)); }
            catch (Exception e) { throw new GeneralSecurityException("Cannot parse Ed25519 private key (need provider)", e); }
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(pk); s.update(data); return s.sign();
        }

        public boolean verify(byte[] data, File sigFile, File publicKey) throws Exception {
            if (!isAlgAvailable("Signature", "Ed25519")) throw new GeneralSecurityException("Ed25519 unavailable (install a provider)");
            byte[] sig = fromBase64IfAscii(readAll(sigFile));
            String p = Files.readString(publicKey.toPath(), StandardCharsets.US_ASCII);
            String base = extractPem(p, "PUBLIC KEY");
            byte[] der = Base64.getMimeDecoder().decode(base);
            PublicKey pub;
            try { pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der)); }
            catch (Exception e) { throw new GeneralSecurityException("Cannot parse Ed25519 public key (need provider)", e); }
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(pub); s.update(data); return s.verify(sig);
        }

        public byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception {
            throw new GeneralSecurityException("Ed25519 is a signature scheme; no encryption");
        }
        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception {
            throw new GeneralSecurityException("Ed25519 is a signature scheme; no decryption");
        }
    }

    static class Blake3Plugin implements CryptoPlugin {
        public String name(){ return "blake3"; }

        public String hash(String alg, byte[] data) throws Exception {
            // Requires provider that exposes "BLAKE3-256"
            if (!isAlgAvailable("MessageDigest", "BLAKE3-256")) throw new GeneralSecurityException("BLAKE3-256 unavailable (install provider)");
            MessageDigest md = MessageDigest.getInstance("BLAKE3-256");
            byte[] d = md.digest(data);
            return "BLAKE3-256:\nHEX  " + hex(d) + "\nB64  " + Base64.getEncoder().encodeToString(d) + "\n";
        }
        public byte[] sign(byte[] data, File privateKey) throws Exception { throw new GeneralSecurityException("blake3: sign not supported"); }
        public boolean verify(byte[] data, File sigFile, File publicKey) throws Exception { throw new GeneralSecurityException("blake3: verify not supported"); }
        public byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("blake3: encrypt not supported"); }
        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("blake3: decrypt not supported"); }
    }

    static class Argon2idPlugin implements CryptoPlugin {
        public String name(){ return "argon2id"; }

        public String hash(String alg, byte[] data) throws Exception {
            // Requires provider with "Argon2id" SecretKeyFactory (e.g., BC)
            if (!isAlgAvailable("SecretKeyFactory", "Argon2id")) throw new GeneralSecurityException("Argon2id unavailable (install provider)");
            throw new GeneralSecurityException("Argon2id present, but this minimal stub omits parameterization. Use your provider's API directly.");
        }
        public byte[] sign(byte[] data, File privateKey) throws Exception { throw new GeneralSecurityException("argon2id: sign N/A"); }
        public boolean verify(byte[] data, File sigFile, File publicKey) throws Exception { throw new GeneralSecurityException("argon2id: verify N/A"); }
        public byte[] encrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("argon2id: encrypt N/A"); }
        public byte[] decrypt(String cipher, byte[] data, String keyFile, String ivFile) throws Exception { throw new GeneralSecurityException("argon2id: decrypt N/A"); }
    }

    /* ---------------- Capability probe ---------------- */

    static boolean isAlgAvailable(String service, String alg) {
        try {
            switch (service) {
                case "Signature": Signature.getInstance(alg); return true;
                case "MessageDigest": MessageDigest.getInstance(alg); return true;
                case "SecretKeyFactory": SecretKeyFactory.getInstance(alg); return true;
                default: return false;
            }
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
