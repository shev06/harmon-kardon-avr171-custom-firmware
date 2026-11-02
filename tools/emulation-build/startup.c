/*
 * Minimal Cortex-M startup file for toolchain/emulation validation only.
 * Vector table shape mirrors what was found in the real firmware (initial
 * SP, then Reset_Handler as entry 1), not a full CMSIS vector table.
 */
#include <stdint.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;

void Reset_Handler(void);
void Default_Handler(void);

void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));

/* Initial SP placeholder: top of our 128K test RAM region (0x20000000 + 0x20000). */
#define TEST_STACK_TOP 0x20020000UL

__attribute__((section(".isr_vector")))
const uint32_t vector_table[] = {
    TEST_STACK_TOP,
    (uint32_t)&Reset_Handler,
    (uint32_t)&NMI_Handler,
    (uint32_t)&HardFault_Handler,
};

volatile uint32_t loop_counter = 0;

void Reset_Handler(void) {
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }
    dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0;
    }

    extern int main(void);
    main();

    while (1) { }
}

void Default_Handler(void) {
    while (1) { }
}
