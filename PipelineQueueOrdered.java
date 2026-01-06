import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

public class PipelineQueueOrdered {

    static final class Chunk {
        final int index;
        final byte[] bytes;
        Chunk(int index, byte[] bytes) { this.index = index; this.bytes = bytes; }
    }

    public static void exportConcurrently(List<String> items, Path outFile)
            throws IOException, InterruptedException {

        int threads = Math.max(2, Runtime.getRuntime().availableProcessors());
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        // Bounded => backpressure + bounded memory
        int queueCapacity = threads * 8;
        BlockingQueue<Chunk> queue = new ArrayBlockingQueue<>(queueCapacity);

        // Used to report transform errors back to the caller
        AtomicReference<Throwable> workerError = new AtomicReference<>();

        // Poison pill to stop writer
        Chunk POISON = new Chunk(-1, new byte[0]);

        Thread writer = new Thread(() -> {
            // Pending map buffers only out-of-order chunks (bounded-ish by queueCapacity)
            Map<Integer, byte[]> pending = new HashMap<>();
            int next = 0;

            try (BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(outFile))) {
                while (true) {
                    Chunk c = queue.take();
                    if (c.index == -1) break;

                    pending.put(c.index, c.bytes);

                    while (true) {
                        byte[] b = pending.remove(next);
                        if (b == null) break;
                        out.write(b);
                        next++;
                    }
                }

                // If poison arrives early (due to error), we may still have some pending.
                // Usually we stop fast on error, so we don't try to flush the rest.
                out.flush();
            } catch (Throwable t) {
                workerError.compareAndSet(null, t);
            }
        }, "writer");

        writer.start();

        try {
            // Submit transform tasks
            for (int i = 0; i < items.size(); i++) {
                final int idx = i;
                final String item = items.get(i);

                pool.execute(() -> {
                    // If any error already happened, stop producing
                    if (workerError.get() != null) return;

                    try {
                        String line = "ITEM=" + item.toUpperCase(Locale.ROOT) + "\n";
                        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);

                        // blocks if writer is behind => backpressure
                        queue.put(new Chunk(idx, bytes));
                    } catch (Throwable t) {
                        workerError.compareAndSet(null, t);
                    }
                });
            }
        } finally {
            pool.shutdown();
            if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                pool.shutdownNow();
            }

            // Stop writer (even if we had an error)
            queue.put(POISON);
            writer.join();
        }

        // Surface worker/writer errors to the caller
        Throwable t = workerError.get();
        if (t != null) {
            if (t instanceof IOException ioe) throw ioe;
            if (t instanceof InterruptedException ie) throw ie;
            throw new RuntimeException(t);
        }
    }

    public static void main(String[] args) throws Exception {
        exportConcurrently(List.of("alpha", "beta", "gamma"), Path.of("out.txt"));
    }
}
