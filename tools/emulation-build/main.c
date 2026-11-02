/*
 * Trivial test body for toolchain/linker validation. Not derived from or
 * resembling the real firmware's application code in any way -- this just
 * proves our confirmed memory map (FLASH origin 0x08010000, RAM origin
 * 0x20000000) produces a loadable image a Cortex-M4 target can execute.
 */
#include <stdint.h>

extern volatile uint32_t loop_counter;

int main(void) {
    while (1) {
        loop_counter++;
    }
}
