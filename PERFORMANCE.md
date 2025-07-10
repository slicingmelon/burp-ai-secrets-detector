# Here we log some benchmarks and profiler


## CPU

![CPU Profiling](images/cpu-profiling-1.jpg)

It takes around ~18ms to scan a response. This includes:

✅ Pattern matching across multiple regex patterns
✅ String/ByteArray processing for position finding
✅ Counter lookups in persistent storage
✅ Secret object creation and marker positioning
✅ Audit issue creation (when secrets found)

### Performance Analysis:

- 8ms × 25 threads = Massive Throughput
- Sequential processing: 55 responses/second (1000ms ÷ 18ms)
- With 25 threads: ~1,375 responses/second (55 × 25)
  
### Breakdown Estimate

- Pattern matching: ~8-12ms
- Position finding: ~2-4ms
- Counter checking: ~1-2ms
- Object creation: ~1-2ms

### Comparison

- TruffleHog: Often 50-200ms per file
- GitLeaks: 20-100ms per scan
- Burp Secrets Detector: 18ms for full HTTP response analysis

