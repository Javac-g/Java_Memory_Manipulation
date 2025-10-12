import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.BitSet;
import java.util.Locale;
import java.util.StringJoiner;

/**
 * BitsBytesPlayground - quick toolkit for bit/byte/hex/oct/binary manipulations & pretty printing.
 *
 * Run: javac BitsBytesPlayground.java && java BitsBytesPlayground
 */
public class BitsBytesPlayground {

    /* -------------------------
       Basic formatters & parsers
       ------------------------- */

    // Return an 8-bit binary string for a byte, e.g. 01010101
    public static String byteToBinaryString(byte b) {
        int v = b & 0xFF;
        return String.format("%8s", Integer.toBinaryString(v)).replace(' ', '0');
    }

    // Return binary string for any integer with given width (e.g., 32)
    public static String intToBinaryString(int value, int width) {
        String s = Integer.toBinaryString(value & ((width == 32) ? -1 : ((1 << width) - 1)));
        if (s.length() > width) s = s.substring(s.length() - width);
        return String.format("%" + width + "s", s).replace(' ', '0');
    }

    // Hex string (lowercase) with leading 0x (for a byte)
    public static String byteToHex(byte b) {
        return String.format("0x%02x", b & 0xFF);
    }

    // Octal string for a byte (leading 0)
    public static String byteToOctal(byte b) {
        return String.format("0%03o", b & 0xFF);
    }

    // Parse hex (with or without 0x) into byte[]
    public static byte[] parseHexStringToBytes(String hex) {
        String s = hex.replaceAll("0x", "").replaceAll("[^0-9A-Fa-f]", "");
        if (s.length() % 2 != 0) s = "0" + s;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    // Parse binary string -> bytes (groups of 8)
    public static byte[] parseBinaryStringToBytes(String bin) {
        String s = bin.replaceAll("[^01]", "");
        int pad = (8 - (s.length() % 8)) % 8;
        if (pad > 0) s = "0".repeat(pad) + s;
        byte[] out = new byte[s.length() / 8];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 8, i * 8 + 8), 2);
        }
        return out;
    }

    /* -------------------------
       Bit-level utilities
       ------------------------- */

    // Test bit at index (0 = LSB) of a byte
    public static boolean testBit(byte b, int bitIndex) {
        if (bitIndex < 0 || bitIndex > 7) throw new IllegalArgumentException("bitIndex 0..7");
        return ((b >> bitIndex) & 1) == 1;
    }

    // Set bit
    public static byte setBit(byte b, int bitIndex) {
        return (byte) (b | (1 << bitIndex));
    }

    // Clear bit
    public static byte clearBit(byte b, int bitIndex) {
        return (byte) (b & ~(1 << bitIndex));
    }

    // Toggle bit
    public static byte toggleBit(byte b, int bitIndex) {
        return (byte) (b ^ (1 << bitIndex));
    }

    // Get an int's bytes (big or little endian)
    public static byte[] intToBytes(int value, ByteOrder order) {
        ByteBuffer buf = ByteBuffer.allocate(4).order(order);
        buf.putInt(value);
        return buf.array();
    }

    // Read int from bytes with order
    public static int bytesToInt(byte[] b, ByteOrder order) {
        ByteBuffer buf = ByteBuffer.wrap(b).order(order);
        return buf.getInt();
    }

    // Convert a BitSet to a binary string (msb-first or lsb-first)
    public static String bitSetToBinary(BitSet bits, int length, boolean msbFirst) {
        StringBuilder sb = new StringBuilder(length);
        if (msbFirst) {
            for (int i = length - 1; i >= 0; i--) sb.append(bits.get(i) ? '1' : '0');
        } else {
            for (int i = 0; i < length; i++) sb.append(bits.get(i) ? '1' : '0');
        }
        return sb.toString();
    }

    /* -------------------------
       Pretty printers / tables
       ------------------------- */

    // Print a byte array as a column table: index | hex | dec | oct | bits
    public static void printByteTable(byte[] data) {
        System.out.println("Idx | Hex   | Dec    | Oct   | Bits");
        System.out.println("----+-------+--------+-------+----------------");
        for (int i = 0; i < data.length; i++) {
            byte b = data[i];
            String row = String.format(Locale.ROOT, "%3d | %5s | %6d | %5s | %s",
                    i, byteToHex(b), b & 0xFF, byteToOctal(b), byteToBinaryString(b));
            System.out.println(row);
        }
    }

    // Return CSV string for bytes: idx,hex,dec,octor,binary
    public static String bytesToCSV(byte[] data, boolean header) {
        StringBuilder sb = new StringBuilder();
        if (header) sb.append("idx,hex,dec,oct,binary\n");
        for (int i = 0; i < data.length; i++) {
            byte b = data[i];
            sb.append(i).append(',')
              .append(byteToHex(b)).append(',')
              .append(b & 0xFF).append(',')
              .append(byteToOctal(b)).append(',')
              .append(byteToBinaryString(b)).append('\n');
        }
        return sb.toString();
    }

    // Save CSV to file
    public static void saveCSV(File out, String csv) throws FileNotFoundException {
        try (PrintWriter pw = new PrintWriter(out)) {
            pw.print(csv);
        }
    }

    /* -------------------------
       Demo / Examples
       ------------------------- */

    public static void main(String[] args) throws Exception {
        System.out.println("=== BitsBytesPlayground Demo ===");

        // Example 1: raw bytes from a string
        String text = "Hi!";
        byte[] bytes = text.getBytes("UTF-8");
        System.out.printf("String: \"%s\" -> bytes[] length=%d%n", text, bytes.length);
        printByteTable(bytes);
        System.out.println();

        // Example 2: parse hex and binary
        byte[] hexParsed = parseHexStringToBytes("0xDEADBEEF");
        System.out.println("Parsed 0xDEADBEEF ->");
        printByteTable(hexParsed);
        System.out.println();

        byte[] binParsed = parseBinaryStringToBytes("11011110101011011011111011101111"); // same as deadbeef
        System.out.println("Parsed binary ->");
        printByteTable(binParsed);
        System.out.println();

        // Example 3: test/set/clear/toggle bit
        byte b = (byte) 0b00001111;
        System.out.println("Original byte: " + byteToBinaryString(b));
        System.out.println("test bit 3 (0-based LSB): " + testBit(b, 3));
        b = setBit(b, 7);   // set MSB
        System.out.println("After set MSB -> " + byteToBinaryString(b));
        b = clearBit(b, 3); // clear bit 3
        System.out.println("After clear bit3 -> " + byteToBinaryString(b));
        b = toggleBit(b, 0); // toggle LSB
        System.out.println("After toggle bit0 -> " + byteToBinaryString(b));
        System.out.println();

        // Example 4: int -> bytes with endianess
        int v = 0x0A0B0C0D;
        System.out.printf("Int 0x%08X as bytes (big-endian):%n", v);
        printByteTable(intToBytes(v, ByteOrder.BIG_ENDIAN));
        System.out.println("as little-endian:");
        printByteTable(intToBytes(v, ByteOrder.LITTLE_ENDIAN));
        System.out.println();

        // Example 5: BitSet demo
        BitSet bits = new BitSet(16);
        bits.set(0); // LSB
        bits.set(3);
        bits.set(15); // a high bit
        System.out.println("BitSet (lsb-first) -> " + bitSetToBinary(bits, 16, false));
        System.out.println("BitSet (msb-first) -> " + bitSetToBinary(bits, 16, true));
        System.out.println();

        // Example 6: export CSV table
        String csv = bytesToCSV(hexParsed, true);
        System.out.println("CSV preview (first 4 lines):");
        String[] lines = csv.split("\n");
        for (int i = 0; i < Math.min(lines.length, 4); i++) System.out.println(lines[i]);
        // Save to file (comment/uncomment)
        File out = new File("bytes_table.csv");
        saveCSV(out, csv);
        System.out.println("CSV saved to " + out.getAbsolutePath());

        System.out.println("\n=== End demo ===");
    }
}
