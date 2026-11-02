/*
 * Minimal linker script modeling the CONFIRMED AVR1710 STM32F4 memory map,
 * for toolchain/emulation validation only. This is NOT used to build any
 * image intended for the real receiver's flash.
 *
 * FLASH layout (confirmed from live sector tables at 0x0800d0a8/0x0800d0dc
 * in the real firmware image, see firmware-analysis/subsystem-findings.md):
 *   Sectors 0-3 (0x08000000-0x0800FFFF, 4x16KiB = 64KiB): bootloader region,
 *     protected -- the real update loop never erases/programs these sectors.
 *   Sectors 4-11 (0x08010000-0x080FFFFF, 64KiB+7x128KiB = 960KiB): application
 *     region -- this is what "MCU UPDATE" erases and reprograms.
 *
 * RAM origin 0x20000000 confirmed by both vector tables' initial SP values
 * (bootloader SP=0x20009188, application SP=0x2001d300). Size here is a
 * conservative placeholder (128K) for test-program linking only; the real
 * chip's exact RAM size has not been independently confirmed.
 */

MEMORY
{
  BOOTLOADER (rx)  : ORIGIN = 0x08000000, LENGTH = 64K
  APPFLASH   (rx)  : ORIGIN = 0x08010000, LENGTH = 960K
  RAM        (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

ENTRY(Reset_Handler)

SECTIONS
{
  /* Test builds link into the APPFLASH region by default so a build never
     collides with the (protected, untouched) bootloader address range. */
  .isr_vector : {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > APPFLASH

  .text : {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
  } > APPFLASH

  _sidata = LOADADDR(.data);

  .data : {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM AT > APPFLASH

  .bss : {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  ._user_heap_stack : {
    . = ALIGN(8);
    . = . + 0x1000; /* placeholder heap/stack reservation */
    . = ALIGN(8);
  } > RAM

  /DISCARD/ : { *(.comment) *(.ARM.attributes) }
}
