# Fuzzing the module update path

Depth to `tests/fuzz_smoke.rs`'s breadth. That file runs seeded mutation on
every commit and needs only stable; these targets need nightly and are run
deliberately.

    cargo +nightly fuzz run apply_patch     -- -max_total_time=600
    cargo +nightly fuzz run parse_prefix    -- -max_total_time=600
    cargo +nightly fuzz run verify_package  -- -max_total_time=600

## Why these three

Everything here parses bytes an attacker controls, and the ordering matters:

- `parse_prefix` and `verify_package` run **before** any signature has been
  checked. Anything reachable on the way to that check is exposed.
- `apply_patch` is the most exposed of all. Its payload is **never signed** -
  the manifest commits only to the RESULT hash - so a properly signed package
  can legitimately carry arbitrary bytes here, caught only at the end. bsdiff
  and ruzstd are handed hostile input by design, and neither is our code.

`verify_package` is not trying to forge a signature; it cannot, and if it ever
did the assertion inside would fire. It exercises the path up to that point.

## Baseline

First run, no findings:

| target | executions | duration |
|---|---|---|
| apply_patch | 1,186,804 | 181 s |
| parse_prefix | 50,068,505 | 91 s |
| verify_package | 580,466 | 91 s |

The execution-rate spread is informative rather than noise: `parse_prefix` is
pure parsing, `verify_package` spends its time in ed25519, and `apply_patch`
sits between because it decompresses.

## Known cost, not a finding

A hostile delta can consume up to `MAX_MODULE_BYTES` of decompression before
failing. That bound is deliberate - it is what stops a decompression bomb -
but it is real work per rejected package. Committing the expected payload
length in the manifest, which IS signed, would let a mismatched payload be
rejected before decompression starts.
