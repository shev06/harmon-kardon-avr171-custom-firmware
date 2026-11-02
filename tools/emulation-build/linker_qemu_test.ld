/*
 * QEMU-ONLY validation variant: places the test image at 0x08000000, the
 * architectural Cortex-M boot address (and where QEMU's netduinoplus2 /
 * olimex-stm32-h405 machine models expect a -kernel ELF's vector table).
 * This is purely to validate the toolchain+emulator pipeline in isolation;
 * it has no connection to the real bootloader's protected flash region.
 */

MEMORY
{
  QEMU_TEST_FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM             (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector : {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > QEMU_TEST_FLASH

  .text : {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
  } > QEMU_TEST_FLASH

  _sidata = LOADADDR(.data);

  .data : {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM AT > QEMU_TEST_FLASH

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
    . = . + 0x1000;
    . = ALIGN(8);
  } > RAM

  /DISCARD/ : { *(.comment) *(.ARM.attributes) }
}
