# VulnHunterX — Finding Report

**Repository**: vorbis (`8de70016`)
**Rule**: `cpp/alloca-in-loop`
**File**: `lib/vorbisfile.c:2290`
**Model**: glm-5.1
**Generated**: 2026-05-12 14:19:09

---

## Verdict: True Positive

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **CWE** | CWE-770 |
| **Tags** | reliability, correctness, security |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.85) |
| **Iterations** | 1 |
| **Time** | 43.0s |
| **Tokens** | 2,762 |

**Message**: Stack allocation is inside a `for(...;...;...)` loop.

---

## Data Flow

`vi1->channels` (from audio file header, line 2289) → loop bound (line 2289) → `alloca` sink (line 2290, called once per channel); `n1` from `vorbis_info_blocksize` (line 2283) → allocation size per iteration (line 2290)

---

## Reasoning

`alloca()` is called inside a for loop (line 2290) bounded by `vi1->channels`. While channels is normally 1-2 in legitimate Vorbis files, a maliciously crafted file could set an arbitrarily high channel count, causing unbounded stack growth. Combined with the per-iteration allocation of `sizeof(float)*n1` (up to ~16KB), a crafted file could easily overflow the stack. The CodeQL precision is 'high' and severity is 7.5, consistent with a real DoS vulnerability via stack overflow in a library that parses untrusted input.

---

## Guided Question Answers

1. Yes. `alloca(sizeof(**lappcm)*n1)` is called on line 2290, which is inside a `for` loop iterating over `vi1->channels` (line 2289). Additionally, `alloca(sizeof(*lappcm)*vi1->channels)` is called on line 2282 outside any loop, which is safe.
2. The iteration count is bounded by `vi1->channels`, which comes from the Vorbis audio stream header. This value is typically 1 (mono) or 2 (stereo), but could be forged to a higher value in a malicious file.
3. The per-iteration allocation size is `sizeof(**lappcm)*n1`, where `sizeof(**lappcm)` is `sizeof(float)` (4 bytes). `n1` is derived from `vorbis_info_blocksize(vi1,0)` (up to 8192) right-shifted by `1+hs1`. Each allocation is bounded to roughly 4×4096 = 16KB in standard configurations. An attacker can influence both channel count and blocksize via a crafted file.
4. Default stack sizes are typically 1–8MB. With standard channels (1–2), total stack usage is negligible (~16–32KB). However, a malicious file specifying an arbitrarily high channel count (e.g., 10000) would allocate ~10000×16KB = 160MB, far exceeding any stack limit.
5. Yes. Using `malloc(sizeof(**lappcm)*n1)` inside the loop, or a single `malloc(sizeof(**lappcm)*n1*vi1->channels)` before the loop, would be safe and functionally equivalent.
6. No. `ov_crosslap` is not recursive, so the alloca does not compound with recursion depth.
