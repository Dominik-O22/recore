---
name: verify-x87-fast-path
description: Prove with Kani that the x87 float fast path in crates/machine/src/x87.rs gives the same bits as the exact software path. Use when a change touches `fast`, `native`, `from_native`, `compute`, `compute_exact`, `applies`, `Control`, or the rounding and arithmetic helpers of the exact path in that file, or `mask`/`signed` in crates/machine/src/ops.rs, or when an x87 result in lifted code or `recore-mcp run` disagrees with the processor.
---

# Verify the x87 fast path

`x87::compute` tries `fast` first: it does the operation on the machine's own `f64` and checks
whether that answer can be trusted. When `fast` answers, `compute` returns its answer and never
runs `compute_exact`. Lifted code reaches it through `Cpu::float` (`f_add`, `f_mul` and the rest)
and `Cpu::op` in crates/machine/src/lib.rs, and recore's emulator through `Emulator::execute` in
crates/mcp/src/emulate.rs.

**The property.** Wherever `fast` answers, it gives the bits `compute_exact` gives, for every
input that `applies` sends to the x87 code.

**The harm when it breaks.** A lifted program or `recore-mcp run` gets a float the processor would
not give, with no error, and the tests that compare against the processor only notice when their
random inputs happen to land on the case.

## Run it

Kani is pinned in mise.verify.toml, which plain `mise install` does not load. The first time:

```
MISE_ENV=verify mise install
MISE_ENV=verify mise exec -- cargo kani setup
```

Then, from the repository root:

```
MISE_ENV=verify mise run x87-proofs              # all 47 proofs, about 10 minutes on 16 cores
MISE_ENV=verify mise run x87-proofs -- add::     # the proofs whose name contains `add::`
```

It prints a line per proof (`passed`, `FAILED` or `ERROR` with its log, or `TIMEOUT`) and writes
target/kani-logs/summary.txt, and exits nonzero unless all passed, or when the filter matches no
proof. A `passed` proof marked `(fast never answers)` saw `fast` decline every input: it holds
because there is nothing to check, which is right for an operation with no fast case and worth a
look for one that has one. `KANI_TIMEOUT` sets the seconds per
proof (900 by default). Run the
proofs of the operations your change touches first; most take under 40 seconds, and add, sub,
mult, div and the `_by_power` proofs take 2 to 10 minutes each. A change to `native`,
`from_native` or the exact path's helpers touches all of them.

## Expected failures at the sync commit

The code at the sync commit breaks the property. These 10 proofs fail, and the other 37 pass:

```
add::to_4  add::to_8  add::to_10  sub::to_4  sub::to_8  sub::to_10
mult_by_power::to_8  mult_by_power::to_10  div_by_power::to_8  div_by_power::to_10
```

They are two bugs in `fast`. Both were checked against this machine's x87 with `fmul` and `fadd`
under the same control word, and the processor gives the exact path's answer.

1. **Rounding up to the least normal number.** The fast path rejects a result that is not a
   normal `f64` (or, at precision 24, a normal `f32`), but a value just below the least normal
   number can round up to it. The `f64` rounding then rounds with a subnormal's few bits, while
   the x87 keeps the full precision in its wider exponent range. Example, precision 53, into a
   10-byte register: (1 − 2⁻⁵³) × 2⁻¹⁰²². The exact path gives 0x3c00fffffffffffff800 (the
   product exactly) and `fast` gives 0x3c018000000000000000 (2⁻¹⁰²²). The precision-24 form:
   (1 − 2⁻²⁴)·2⁻⁹⁹² × 2⁸⁶⁶ gives 2⁻¹²⁶ from `fast` and 2⁻¹²⁶ − 2⁻¹⁵⁰ from the exact path. Into 4
   bytes both paths round into the float's own subnormals and agree, which is why the `to_4`
   proofs of mult and div pass.
2. **Rounding twice at precision 24.** `fast` rounds to 53 bits in `f64` and then to 24 bits, and
   its comment says that is the same as rounding once because 53 ≥ 2·24 + 2. That theorem needs
   the operands to have 24 bits. An x87 register can hold 64. Example, FAdd under precision 24:
   (1 + 2⁻²⁴) + (1 + 2⁻²⁴)·2⁻⁵¹². The `f64` sum is 1 + 2⁻²⁴, a tie, which rounds to 1. The exact
   sum is just above the tie and rounds to 1 + 2⁻²³.

A fix that declines `±f64::MIN_POSITIVE` (and `±f32::MIN_POSITIVE` at precision 24), and at
precision 24 declines operands with more than 24 significant bits, makes every proof pass and
keeps `cargo test -p recore-machine` passing. It was tried and then dropped, because the
verification work did not change product code. When a fix lands, the 10 lines above should turn
to `passed`. Then delete this section and move the sync commit.

## Read a failure

A `FAILED` line is either a bug in `fast` or a gap between Kani's model and the processor. The
log's `Failed Checks` line names the check:

- `"fast gives {bits:#x}, the exact path ..."` is the property. Get the case:
  1. `cd crates/machine && MISE_ENV=verify mise exec -- cargo kani -Z concrete-playback --concrete-playback=print --harness x87::proofs::<op>::<to_N> --exact > ../../target/kani-logs/play.log`
  2. Copy the `#[test] fn kani_concrete_playback_...` block from the end of that log to the end of
     src/x87/proofs.rs, and change its last line's `to_N` to `<op>::to_N`.
  3. `MISE_ENV=verify mise exec -- cargo kani playback -Z concrete-playback` panics with the
     operation, the result width, the operands as `(bits, width)` in hex (width `a` is 10), the
     control word, and both answers.
  4. Delete the pasted test.
- Any other check (`NaN on division`, an overflow, an index out of bounds) fails in code the
  property runs. Kani reports a NaN from a float operation as a failure, but Rust defines it. An
  overflow is a panic in a build with overflow checks.

Before you call it a bug, run the case natively: call `fast` and `compute_exact` from a scratch
`#[cfg(test)]` test in x87.rs, and compare with the processor through the `x87!` macro in its
`hardware` tests. If native `fast` and `compute_exact` agree, the gap is Kani's model. Kani
0.68's `f64::sqrt` is one such gap: it gives √(1.5·2⁶⁴⁸) the wrong bits, which is why no proof
covers FSqrt. If they disagree natively and the processor sides with the exact path, it is a
bug in `fast`. If the processor sides with `fast`, the exact path is wrong. That is outside this
property but worth an issue.

An `ERROR` is Kani failing to build or run; the log says why. A `TIMEOUT` proves nothing either
way. Raise `KANI_TIMEOUT`, or lower the bound in `proofs!`
and say so in the coverage record.

## What it covers

Each proof is one operation into one width of result: `to_1` for a comparison, `to_4`, `to_8` and
`to_10` for the others. It enumerates every operand width (4, 8 or 10 bytes, or for Int2Float integers of 1,
2, 4, 8 and 10 bytes) and leaves symbolic every operand bit pattern, every 16-bit control word,
and so every precision and rounding. The bounds:

| Operation | Significand bits per operand |
| --- | --- |
| FAdd, FSub, comparisons, FNan, FNeg, FAbs, Float2Float, Int2Float, Trunc, Ceil, Floor, Round | all |
| FMult | 8 and 8, and again (`mult_by_power`) any and 1 |
| FDiv | 4 and 4, and again (`div_by_power`) any and 1 |
| FSqrt | not covered: Kani's `f64::sqrt` model is wrong |

FMult and FDiv are bounded because a SAT solver cannot prove a full-width multiplier or divider
equal to another in useful time. Full width times 8 bits found bugs but did not finish a proof
in 30 minutes. The `_by_power` proofs take a full first operand with a power of two second, the
shape of bug 1, and finish in 3 minutes. A bug that needs two wide operands to multiply or divide
is outside the proofs. `the_native_path_matches_the_exact_one` and the `hardware` tests in
x87.rs still sample those cases, and FSqrt.

`fast` has no case for FNeg, FAbs, Trunc, Ceil, Floor or Round today, so their proofs pass with
`(fast never answers)`; they are there for the day one is added. Trunc into 1 or 2 bytes, as
`fist m16` makes, has no proof; add the widths with a fast case for it.

`Cpu::controlled` in crates/machine/src/lib.rs, behind `f64_add`, `f64_mult` and the rest, which
lifted code that keeps the x87 registers as `f64` calls, has a fast path of its own and no proof.
By reading, not proof: at precision 24 it narrows the `f64` result with `as f32`, which has the
shapes of both bugs above.

The proofs trust `compute_exact` as the reference. They don't check it against the processor;
the `hardware` tests do that. FDiv leaves out zero divided by zero, which `fast` declines anyway
(it declines every zero divisor), because `fast` divides first and Kani would report the NaN.

## Coverage record

Sync commit: `f822765`. The proofs describe these at that commit:

- crates/machine/src/x87.rs: `fast`, `native`, `from_native`, `compute`, `compute_exact`,
  `applies`, `Control::from_word`, `Format`, `decode`, `encode`, `rounds_up`, `round`, `exact`,
  `finish`, `propagate`, `shift_right`, `add`, `multiply`, `divide`, `integral`, `to_integer`,
  `compare`
- crates/machine/src/ops.rs: `mask`, `signed`, `fits`, `signed_min`, and the float members of
  `Code`
- The proofs: crates/machine/src/x87/proofs.rs, crates/machine/proofs.sh, mise.verify.toml

To see whether the covered code moved since the sync commit (the commit that added these proofs
changed only the `mod proofs` line of x87.rs):

```
git log --oneline f822765..HEAD -- crates/machine/src/x87.rs crates/machine/src/ops.rs
```

## Keep it in step

- A new fast case for an operation already in `proofs!` is checked as it is. Run that
  operation's proofs.
- A new float `Code` that `applies` accepts needs a line in `proofs!` (`compare name: Code, [bits,
  bits];` for one that writes a byte, `float` for the rest) and, if it takes two operands, a place
  in the `matches!` list of `every_operand`.
- A new operand or result width goes in `FLOATS` or the Int2Float list, and `float` needs its
  fraction width.
- If `compute_exact` gains an error path that formats a message, keep the widths constant in
  the proofs. Symbolic widths make Kani unroll `format!` without end.
- Move the sync commit only after you have read the covered functions at the new commit,
  confirmed the proofs still describe them, and run the proofs for every operation the change
  touched. Update the expected failures to match the run.
