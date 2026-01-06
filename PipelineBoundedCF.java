import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.IntStream;

public class PipelineBoundedCF {

    public static void exportConcurrently(List<String> items, File outFile) throws Exception {
        int threads = Math.max(2, Runtime.getRuntime().availableProcessors());
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        // Limit in-flight tasks
        int maxInFlight = threads * 4;
        Semaphore sem = new Semaphore(maxInFlight);

        try (BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(outFile))) {
            @SuppressWarnings("unchecked")
            CompletableFuture<byte[]>[] futures = new CompletableFuture[items.size()];

            for (int i = 0; i < items.size(); i++) {
                sem.acquire();
                final String item = items.get(i);

                futures[i] = CompletableFuture.supplyAsync(() -> {
                    String line = "ITEM=" + item.toUpperCase(Locale.ROOT) + "\n";
                    return line.getBytes(StandardCharsets.UTF_8);
                }, pool).whenComplete((r, t) -> sem.release());
            }

            // Preserve order, but without holding all byte[] at once beyond maxInFlight-ish
            for (CompletableFuture<byte[]> f : futures) {
                try {
                    fileOut.write(f.get()); // get() gives checked exceptions
                } catch (ExecutionException ee) {
                    throw new RuntimeException("Worker failed", ee.getCause());
                }
            }
            fileOut.flush();
        } finally {
            pool.shutdown();
            pool.awaitTermination(1, TimeUnit.MINUTES);
        }
    }

    public static void main(String[] args) throws Exception {
        exportConcurrently(List.of("alpha", "beta", "gamma"), new File("out.txt"));
    }
}
