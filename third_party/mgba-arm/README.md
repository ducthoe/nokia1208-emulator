# Vendored: mGBA ARM7TDMI core

The CPU interpreter from [mGBA](https://github.com/mgba-emu/mgba), obtained
through the Nokia DCT3 emulator. Its source revision is in `DCT3_SOURCE.txt`.

- **Upstream:** https://github.com/mgba-emu/mgba
- **Commit:** `9a36d65767a0ea21616b4d602e2b31eb875b2f18` (see `MGBA_COMMIT.txt`)
- **License:** MPL-2.0 (see `LICENSE`). Every source file retains its original
  MPL header. The DCT3 integration's changes are described below.

As part of this combined GPL-3.0-only emulator, these C sources and headers are
also distributed under GPL-3.0-only using
[MPL 2.0 section 3.3](https://www.mozilla.org/en-US/MPL/2.0/#distribution-of-a-larger-work).
Their SPDX identifiers are `MPL-2.0 OR GPL-3.0-only`. Existing MPL notices and
copyright credits are preserved; the GPL text is in the project-root `LICENSE`.

## Local changes

- `src/arm/arm.c` + `include/.../arm/arm.h` — added **`ARMRaiseFIQ`** (upstream
  only exposed `ARMRaiseIRQ`). It mirrors `ARMRaiseIRQ` but enters `MODE_FIQ` at
  `BASE_FIQ` (0x1C) and masks both F and I. The MAD2 firmware drives the MBUS
  UART (and sleep clock) via FIQ, so the platform must be able to deliver them.

- `include/mgba/internal/arm/macros.h` — the `LOAD_*`/`STORE_*` macros are pointed
  at the **big-endian** variants (`LOAD_32BE`, …) instead of upstream's
  little-endian. The DCT3/MAD2 ARM7TDMI runs big-endian, and the CPU's instruction
  fetch reads memory through these macros (bypassing the `ARMMemory` vtable), so the
  fetch path itself must be big-endian. A simple byte-swap of the flash image can't
  work because the firmware mixes 32-bit ARM and 16-bit Thumb fetches from the same
  bytes. This lets flash inputs retain their original byte order.

## Timing contract

The embedding in `src/rh105.c` supplies the zero-wait data-access cycles:
LDR is 3 cycles (fetch + data + internal), STR is 2, STM is `n+1`, and LDM
is `n+2` before any PC refill. Multiple loads charge one internal cycle for
the whole transfer, not one per register. `ARMWritePC`/`ThumbWritePC` charge
two refill cycles on top of the instruction fetch, giving a taken branch
3 cycles. Do not subtract a refill cycle: that previously slowed the guest's
peripheral clock relative to its executed instructions. Actual Nokia memory
wait states remain unverified.

## What's here

`src/arm/` contains the three interpreter sources:

| file              | role |
|-------------------|------|
| `arm.c`           | core lifecycle: `ARMInit`/`ARMReset`/`ARMRun`, mode switching, IRQ entry/exit |
| `isa-arm.c`       | ARM instruction implementations (execution) |
| `isa-thumb.c`     | Thumb instruction implementations (execution) |

The optional disassembler sources are omitted from this runtime package.

`include/` contains their header dependencies:

- `mgba/internal/arm/*.h` — ARM core, ISA, emitter X-macro tables, macros
- `mgba/core/cpu.h` — `mCPUComponent`, `mMemoryAccessSource` (referenced by `arm.h`)
- `mgba-util/{common,dllexports}.h` — base types + platform macros

## Integration notes

- The CPU reaches memory **only** through the `struct ARMMemory` vtable in
  `arm.h` (`load`/`store` 8·16·32, `loadMultiple`/`storeMultiple`,
  `setActiveRegion`). The platform (`src/rh105.c` at the project root)
  implements that vtable; the core never learns what a phone is.
- The Makefile compiles the three execution sources above; it does not enable
  the disassembler or require a debugger symbol stub.
- To update: re-copy the execution sources and their header dependencies from
  mGBA, preserve the integration changes, and update the revision records.
