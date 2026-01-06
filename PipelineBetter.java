import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.*;

public class PipelineBetter {

    static final class Chunk {
        final int index;
        final byte[] bytes;
        Chunk(int index, byte[] bytes) { this.index = index; this.bytes = bytes; }
    }

    public static void exportConcurrently(List<String> items, Path outFile) throws Exception {
        int threads = Math.max(2, Runtime.getRuntime().availableProcessors());
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        // Bounded queue => backpressure
        int queueCapacity = threads * 4;
        BlockingQueue<Chunk> queue = new ArrayBlockingQueue<>(queueCapacity);

        // A poison pill to stop writer, ma boy
        Chunk POISON = new Chunk(-1, new byte[0]);

        // Writer thread: keeps output in correct order
        Thread writer = new Thread(() -> {
            try (BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(outFile))) {
                int next = 0;
                // store out-of-order chunks temporarily
                ConcurrentHashMap<Integer, byte[]> pending = new ConcurrentHashMap<>();

                while (true) {
                    Chunk c = queue.take();
                    if (c.index == -1) break;

                    pending.put(c.index, c.bytes);

                    // flush in-order chunks as soon as possible
                    while (true) {
                        byte[] b = pending.remove(next);
                        if (b == null) break;
                        out.write(b);
                        next++;
                    }
                }

                out.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, "file-writer");

        writer.start();

        try {
            // Submit tasks with bounded in-flight behavior (queue provides backpressure)
            for (int i = 0; i < items.size(); i++) {
                final int idx = i;
                final String item = items.get(i);

                pool.execute(() -> {
                    try {
                        String line = "ITEM=" + item.toUpperCase(Locale.ROOT) + "\n";
                        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
                        queue.put(new Chunk(idx, bytes)); // blocks if writer is behind => backpressure
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
        } finally {
            pool.shutdown();
            pool.awaitTermination(1, TimeUnit.MINUTES);
            queue.put(POISON);
            writer.join();
        }
    }

    public static void main(String[] args) throws Exception {
        exportConcurrently(List.of("alpha", "beta", "gamma"), Path.of("out.txt"));
    }
}
