# How to Interpret Fuzzing Results

This guide explains how to read and understand the output from cargo-fuzz/libFuzzer.

## Example Output Breakdown

Let's analyze a typical fuzzing session from `fuzz_cli_validators`:

### 1. **Initialization Messages**

```
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 799347744
INFO: Loaded 1 modules   (5439 inline 8-bit counters): 5439 [0x6278ba9e0f70, 0x6278ba9e24af)
INFO: Loaded 1 PC tables (5439 PCs): 5439 [0x6278ba9e24b0,0x6278ba9f78a0)
INFO:       83 files found in /home/admin/code/veracode-workspace/fuzz/corpus/fuzz_cli_validators
INFO: seed corpus: files: 83 min: 1b max: 17b total: 386b rss: 68Mb
```

**What this means:**
- **Seed**: Random seed for reproducibility (you can re-run with same seed using `-seed=799347744`)
- **5439 inline counters**: The fuzzer instrumented 5,439 code locations to track coverage
- **83 files found in corpus**: The fuzzer found 83 interesting test cases from previous runs
- **min: 1b max: 17b**: Corpus inputs range from 1 to 17 bytes in size
- **rss: 68Mb**: Memory usage (Resident Set Size)

### 2. **Execution Log Format**

Each line shows a test execution:

```
#84    INITED cov: 234 ft: 371 corp: 59/296b exec/s: 0 rss: 68Mb
#277   NEW    cov: 234 ft: 372 corp: 60/308b lim: 17 exec/s: 0 rss: 68Mb L: 12/17 MS: 3 EraseBytes-CopyPart-InsertRepeatedBytes-
#520   NEW    cov: 238 ft: 376 corp: 62/319b lim: 17 exec/s: 0 rss: 68Mb L: 3/17 MS: 1 ChangeASCIIInt-
#861   REDUCE cov: 238 ft: 378 corp: 64/339b lim: 17 exec/s: 0 rss: 68Mb L: 2/17 MS: 1 EraseBytes-
```

**Field explanations:**

| Field | Meaning | Example |
|-------|---------|---------|
| `#277` | Test case number | 277th execution |
| `NEW` | Event type | Found new coverage (added to corpus) |
| `REDUCE` | Event type | Found smaller input with same coverage |
| `INITED` | Event type | Corpus initialization complete |
| `cov: 238` | **Code coverage** | 238 basic blocks covered |
| `ft: 376` | **Features** | 376 unique coverage features (edges, comparisons, etc.) |
| `corp: 62/319b` | **Corpus stats** | 62 files totaling 319 bytes |
| `lim: 17` | Max input size | Currently testing inputs up to 17 bytes |
| `exec/s: 0` | Executions/sec | Speed (0 means very fast, not tracked precisely) |
| `rss: 68Mb` | Memory usage | 68 megabytes |
| `L: 12/17` | Input length | This input is 12 bytes, max is 17 |
| `MS: 3 ...` | **Mutation strategy** | How this input was generated |

### 3. **Event Types**

- **INITED**: Fuzzer finished loading the seed corpus
- **NEW**: Discovered new code coverage → **Added to corpus** ✅
- **REDUCE**: Found smaller input with same coverage → **Replaces larger input** 📉
- **pulse**: Periodic status update (if using `-print_pulse_status=1`)

### 4. **Mutation Strategies (MS)**

These show how libFuzzer generated the test case:

| Mutation | Description |
|----------|-------------|
| `EraseBytes` | Removed some bytes |
| `InsertByte` | Added a byte |
| `CopyPart` | Copied part of input to another location |
| `CrossOver` | Combined two corpus entries |
| `ChangeByte` | Modified a byte value |
| `ChangeBit` | Flipped a single bit |
| `ChangeASCIIInt` | Changed ASCII digits |
| `ShuffleBytes` | Reordered bytes |
| `PersAutoDict` | Used dictionary value |
| `InsertRepeatedBytes` | Added repeated byte sequences |
| `CMP` | Based on comparison hint |

Example: `MS: 3 EraseBytes-CopyPart-InsertRepeatedBytes-`
- Applied 3 mutations in sequence
- First erased bytes, then copied parts, then inserted repeated bytes

### 5. **New Function Discovery**

```
NEW_FUNC[1/1]: 0x6278ba930ea0 (/path/to/binary+0x16eea0)
```

**What this means:**
- The fuzzer discovered a **new function** that was never executed before
- This is excellent! It means the fuzzer is finding deeper code paths
- The address helps identify which function was discovered (use `addr2line` or debugger)

### 6. **Dictionary Recommendations**

At the end, libFuzzer suggests useful values:

```
###### Recommended dictionary. ######
"\000\000" # Uses: 37
"+\000" # Uses: 25
"\001\036" # Uses: 18
"\177\000" # Uses: 7
###### End of recommended dictionary. ######
```

**What this means:**
- These byte sequences appeared frequently in successful mutations
- You can save these to a dictionary file and use `-dict=file.dict` for faster fuzzing
- Higher "Uses" count = more effective value

### 7. **Final Statistics**

```
Done 267522 runs in 30 second(s)
```

- **267,522 executions** in 30 seconds = **~8,917 exec/sec** 🚀
- This is excellent throughput!

## Key Metrics to Watch

### 📊 **Coverage Growth (cov: X)**
- **Good**: Coverage increases over time
  ```
  #277   NEW    cov: 234
  #520   NEW    cov: 238  ← +4 blocks
  #863   NEW    cov: 239  ← +1 block
  ```
- **Plateau**: Coverage stops increasing (may need longer run or better corpus)

### 🎯 **Features (ft: X)**
- Tracks unique program behaviors
- More granular than basic block coverage
- Includes edge coverage and comparison feedback

### 📦 **Corpus Size (corp: X/YYYb)**
- **Growing**: Finding new interesting inputs ✅
- **Stable**: Exhausted current search space (may plateau)
- **Shrinking**: REDUCE events making corpus more efficient

### 🔍 **Input Size (lim: X)**
- libFuzzer gradually increases max input size
- Starts small (4 bytes), grows over time
- You can set max with `-max_len=1024`

## What Success Looks Like

### ✅ **Good Fuzzing Session**
```
#1000   NEW    cov: 242 ft: 375 corp: 37/106b
#5000   NEW    cov: 309 ft: 450 corp: 52/245b
#10000  NEW    cov: 358 ft: 637 corp: 127/1495b
```
- Coverage growing steadily
- Discovering NEW and REDUCE events
- No crashes (no `crash-` files in artifacts/)

### ⚠️ **Needs Attention**
```
#100000 NEW    cov: 50 ft: 52 corp: 5/10b
#200000 pulse  cov: 50 ft: 52 corp: 5/10b
#300000 pulse  cov: 50 ft: 52 corp: 5/10b
```
- Coverage stuck at 50 blocks
- No new discoveries
- **Solutions**:
  - Run longer
  - Add better seed inputs to corpus
  - Use dictionary (`-dict=`)
  - Check if code is reachable

## Finding Crashes

### 🐛 **Crash Detection**
If the fuzzer finds a bug:
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
SUMMARY: AddressSanitizer: heap-buffer-overflow
artifact_prefix='./'; Test unit written to ./crash-da39a3ee5e6b4b0d
```

**What to do:**
1. **Reproduce**: `cargo +nightly fuzz run fuzz_target artifacts/crash-da39a3ee5e6b4b0d`
2. **Debug**: Use with debugger or add prints
3. **Minimize**: `cargo +nightly fuzz tmin fuzz_target artifacts/crash-da39a3ee5e6b4b0d`
4. **Fix** the bug!

## Advanced Interpretation

### Coverage Plateaus
If coverage stops growing:
1. **Run longer**: `-max_total_time=3600` (1 hour)
2. **Use multiple cores**: `-jobs=8`
3. **Add seed corpus**: Place interesting inputs in `corpus/<target>/`
4. **Add dictionary**: `-dict=dict.txt`

### Slow Execution
If `exec/s` is low (<1000):
1. Code might have expensive operations (I/O, crypto, etc.)
2. Add `#[inline(never)]` to prevent over-inlining
3. Simplify fuzz target to focus on parsing logic

### Memory Issues
If `rss:` keeps growing:
1. Memory leak in your code
2. Use `-rss_limit_mb=1024` to catch it

## Real Example Analysis

From our `fuzz_cli_validators` run:

```
#84     INITED cov: 234 ft: 371 corp: 59/296b
#1210   NEW    cov: 263 ft: 429 corp: 68/370b    ← Found new function!
#53053  NEW    cov: 356 ft: 633 corp: 124/1468b  ← Major discovery
#90418  NEW    cov: 396 ft: 699 corp: 139/1537b  ← Another big jump
#267522 DONE   cov: 414 ft: 865 corp: 185/2134b
```

**Analysis:**
- Started with 234 blocks covered (from corpus)
- Grew to **414 blocks** (+180 new blocks discovered!)
- Generated **185 interesting test cases**
- Found multiple new functions (NEW_FUNC messages)
- **No crashes** = code is robust! ✅

## Useful Commands

```bash
# Run with stats
cargo +nightly fuzz run target -- -print_final_stats=1

# Run with periodic updates
cargo +nightly fuzz run target -- -print_pcs=1 -print_pulse_status=1

# Limit memory
cargo +nightly fuzz run target -- -rss_limit_mb=2048

# Use dictionary
cargo +nightly fuzz run target -- -dict=dict.txt

# Multiple jobs
cargo +nightly fuzz run target -- -jobs=8

# Focus on small inputs
cargo +nightly fuzz run target -- -max_len=64
```

## Summary

**Key takeaways:**
1. **cov: X** = code coverage (higher is better)
2. **NEW** events = finding new code paths ✅
3. **REDUCE** events = optimizing corpus ✅
4. **NEW_FUNC** = discovered new functions 🎉
5. **No crashes** after many runs = good code quality
6. **Plateau** = may need longer run or better inputs

For our `fuzz_cli_validators`:
- **414 blocks covered** out of 5,439 instrumented locations
- **267,522 executions** in 30 seconds
- **185 test cases** in corpus
- **No crashes found** ✅
