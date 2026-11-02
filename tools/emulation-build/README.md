# AVR1710 QEMU/ARM-GCC emulation environment (read-only validation, NOT for flashing)

Purpose: validate the static-analysis (Ghidra) findings against a real instruction-set
emulator with modeled STM32F4 peripherals, and provide a working ARM Cortex-M toolchain
for any future test/PoC code. This environment never writes to the real firmware file or
to any real hardware -- it only loads a read-only copy of the .fw image into QEMU's RAM.

## Tooling installed (via Homebrew)

- `arm-none-eabi-gcc` 16.2.0, `arm-none-eabi-binutils` 2.47, `arm-none-eabi-gdb` 18.1
- `qemu` 11.1.3 (`qemu-system-arm`)

## Files in this directory

- `linker.ld` -- linker script modeling the CONFIRMED real memory map (bootloader
  0x08000000-0x0800FFFF protected, app 0x08010000-0x080FFFFF, RAM from 0x20000000).
  Used for any *new* test code meant to conceptually target the real app region.
- `linker_qemu_test.ld` -- QEMU-only variant that places code at 0x08000000 (the
  address QEMU's `netduinoplus2`/`olimex-stm32-h405` STM32F405 machine models actually
  fetch the initial SP/PC from). Used only to validate the toolchain itself.
- `startup.c`, `main.c` -- trivial vector-table + loop test program (not derived from
  or resembling the real firmware) used to prove the toolchain/linker/emulator chain
  works end-to-end.
- `test.elf`/`test.bin` (linked via `linker.ld`) and `test0.elf` (linked via
  `linker_qemu_test.ld`) -- build outputs of the above.

## Confirmed working pipeline (toolchain validation)

```
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -nostdlib -nostartfiles \
  -T linker_qemu_test.ld startup.o main.o -o test0.elf
qemu-system-arm -M netduinoplus2 -nographic -monitor none -serial none \
  -kernel test0.elf -S -gdb tcp::PORT
arm-none-eabi-gdb -q -batch -ex "target remote :PORT" -ex "break Reset_Handler" \
  -ex continue -ex "info registers pc sp" -ex "stepi 30" test0.elf
```
Result: PC correctly starts at `Reset_Handler` (0x08000010), SP matches the linker's
stack top, and execution reaches `main()`'s infinite loop as expected. This confirms
the whole toolchain + our understood memory-map conventions are correct.

## Loading the REAL firmware into QEMU (read-only)

QEMU's `-kernel` option refuses raw (non-ELF) binaries on this machine type, so the
real 6 MiB `.fw` is loaded via the generic loader device instead:

```
qemu-system-arm -M netduinoplus2 -nographic -monitor none -serial none \
  -device "loader,file=/Users/allisonbulner/AVR1710_USB(V002_23).fw,addr=0x08000000,cpu-num=0" \
  -S -gdb tcp::PORT
```

Caveat found: the loader device's `cpu-num=0` property sets CPU0's PC directly to
`addr` (0x08000000) rather than performing a proper Cortex-M vector-table reset
fetch, even though it loads the memory correctly beforehand (SP read back as
0x20009188, matching the real vector table's first word exactly). Fix: after
connecting GDB, manually set `$pc` to the real reset vector (`0x0800d36c`, thumb
code address with LSB stripped) before continuing.

### Result: independent cross-validation of the Ghidra clock-init stall

Running from the true reset vector, QEMU halts (branch-to-self) at **0x080082a0** --
the *exact* address Ghidra's no-MMIO P-code emulator predicted as a non-returning
failure loop in the clock-init path (see `subsystem-findings.md`, boot/startup
section). Two independent emulation methods (static P-code interpreter with no
peripheral model at all, and a full QEMU system emulation with real STM32F405 RCC/
Flash peripheral models) converge on the same stall -- strong evidence this is a
genuine property of the firmware's control flow, not an artifact of either tool.

Static disassembly of the clock-init routine (`0x080081b0`-`0x080082a4`, saved at
`../firmware-analysis/clock-init-static-disasm.log`) fully explains why: it's a
classic RCC_DeInit + HSE/PLL bring-up sequence with THREE separate wait conditions,
only the first of which has a timeout:
1. **HSE ready poll** (`RCC_CR` bit 17, address `0x40023800`): polled in a loop with
   an explicit, bounded **1280-iteration timeout** counter. If HSE never becomes
   ready in time, code falls straight through to the permanent halt trap at
   `0x080082a0` (`bne 0x080082a0` at `0x08008238`).
2. **PLL ready poll** (`RCC_CR` bit 25): polled with **no timeout at all** --
   unconditional infinite loop if PLL never locks.
3. **Clock-switch confirmation poll** (`RCC_CFGR` bits [3:2], `SWS`, waiting for
   value `0b10` = PLL selected, address `0x40023808`): also **no timeout**.

Both Ghidra and QEMU stall at step 1, because neither models real HSE crystal
stabilization timing (QEMU's lightweight STM32F405 peripheral model never sets
`HSERDY`, same as Ghidra's no-MMIO emulator). This is a known limitation of both
emulators, not new evidence about real hardware behavior -- but the fact that two
independently-implemented tools agree on the exact address and the exact mechanism
is a meaningful correctness check on the whole reverse-engineering effort so far.

Attempting to patch `RCC_CR`/`RCC_CFGR` memory *after* the CPU already reached the
halt trap does nothing (confirmed): `0x080082a0` is an unconditional `b.n` to
itself with no register re-check, reached only via the one-way `bne` at
`0x08008238`. To get further, the register write must happen *before* the
1280-iteration timeout elapses (e.g. a breakpoint at the clock-init function entry,
`0x080081b0`, followed by a memory patch, followed by continue) -- software
breakpoints via GDB failed silently in this QEMU configuration (writes to the
loaded flash region appear to be ignored, consistent with it being modeled as
read-only), so this needs GDB hardware breakpoints (`hbreak`) instead of `break`
if resumed in a future session.
