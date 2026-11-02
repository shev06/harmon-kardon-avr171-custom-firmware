@ Option 4b: CEC power-off request -> normal "Device sleep" (never the deep power-down)
@
@ Called (instead of FUN_080192e2) from every CEC power-off path in FUN_0802d230 case 4 / case 0x20
@ and from the cave callback trampoline.  Clobbers r0-r3 like the function it replaces.
@
@   if (c030 bit1 == 0) return;                 @ not ON: nothing to do, do not touch the marker
@   c038 &= 0x7f;                               @ drop a stale "go DEEP" marker
@   b = bfb8;                                   @ must be read BEFORE FUN_080192e2 (it can leave bfb8 = 250)
@   c2b5 = 0; c2b6 = 0;                         @ cancel any pending deferral/fade: exactly ONE countdown may
@                                               @ survive, else FUN_08019638 is entered twice (restarts sequencer)
@   if (b >= 100) { c2b5 = 100; return; }       @ power-on sequence still running: defer (stock CEC timer)
@   FUN_080192e2();                             @ normal path: same as the network/button request
@
@ c2b5 and c2b6 are adjacent bytes; two byte stores avoid an unaligned halfword store.

        .syntax unified
        .cpu    cortex-m4
        .thumb
        .text

        .global cec_sleep_helper
        .thumb_func
cec_sleep_helper:
        push    {r4, lr}
        ldr     r4, lit_c030
        ldrb    r0, [r4]
        lsls    r0, r0, #30             @ bit1 -> N
        bpl     done                    @ OFF
        ldr     r4, lit_c038
        ldrb    r0, [r4]
        movs    r1, #0x7f
        ands    r0, r1
        strb    r0, [r4]
        ldr     r4, lit_bfb8
        ldr     r0, [r4]                @ r0 = bfb8
        ldr     r4, lit_c2b5
        movs    r1, #0
        strb    r1, [r4]                @ c2b5 = 0
        strb    r1, [r4, #1]            @ c2b6 = 0
        cmp     r0, #100
        bhs     defer
        bl      FUN_080192e2
        pop     {r4, pc}
defer:
        movs    r0, #100
        strb    r0, [r4]                @ c2b5 = 100
done:
        pop     {r4, pc}

        .align  2
lit_c030:       .word   0x2001c030
lit_c038:       .word   0x2001c038
lit_bfb8:       .word   0x2001bfb8
lit_c2b5:       .word   0x2001c2b5
