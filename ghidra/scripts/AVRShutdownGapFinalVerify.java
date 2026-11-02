import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

// FINAL fresh-reimport verification of the shutdown-gap-closure patch applied
// to the REAL patched deliverable. Must prove, from a brand-new Ghidra import
// of the actual patched file (not the cached pristine-firmware project):
//   1) Both newly-patched call sites (0x080119d0, 0x08011a1e) now branch to
//      the no-op trampoline instead of FUN_08019638.
//   2) The no-op trampoline itself (0x080c8a1a) is unchanged (bx lr + NOPs).
//   3) All 3 previously-patched call sites (rounds 1-4) are unchanged.
//   4) ALL 10 thermal/fault-protection call sites STILL call FUN_08019638
//      directly and unconditionally - i.e. prove the safety-critical paths
//      were NOT accidentally touched by this patch.
//   5) The 2 boot-logic call sites in FUN_08064ede are untouched.
//   6) The volume/mute fix trampoline is untouched.
public class AVRShutdownGapFinalVerify extends ghidra.app.script.GhidraScript {

    private void dumpInsn(String label, long addr) {
        Address a = toAddr(addr);
        Instruction insn = getInstructionAt(a);
        byte[] buf = new byte[4];
        try { currentProgram.getMemory().getBytes(a, buf); } catch (Exception e) {}
        StringBuilder hex = new StringBuilder();
        for (byte b : buf) hex.append(String.format("%02x", b));
        println(label + "  " + a + ": " + insn + "   bytes=" + hex.toString());
    }

    @Override
    public void run() throws Exception {
        println("=== GAP-CLOSURE SITES (expect: bl to 0x080c8a1a) ===");
        dumpInsn("[gap-1, was 2b5-cell expiry]", 0x080119d0L);
        dumpInsn("[gap-2, was 2b6-cell expiry, UNCONDITIONAL]", 0x08011a1eL);

        println("\n=== NO-OP TRAMPOLINE (expect: bx lr then NOPs, unchanged) ===");
        Address a = toAddr(0x080c8a1aL);
        Address end = toAddr(0x080c8a36L);
        while (a.compareTo(end) < 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { println("  " + a + ": [no instruction]"); a = a.add(2); continue; }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }

        println("\n=== ROUNDS 1-4 SITES (expect: bl to 0x080c8a1a, unchanged) ===");
        dumpInsn("[round-1/4 site A]", 0x0801930eL);
        dumpInsn("[round-1/4 site B]", 0x08019348L);
        dumpInsn("[round-1/4 site C]", 0x08019294L);

        println("\n=== SAFETY-CRITICAL THERMAL/FAULT SITES (expect: ALL still bl FUN_08019638 directly, UNTOUCHED) ===");
        long[] safetySites = {
            0x080131c6L, 0x08013312L,   // FUN_08013138 - fault codes 1/2
            0x080135bcL, 0x0801366cL,   // FUN_08013506 - fault codes 3/4
            0x080137b6L, 0x08013926L,   // FUN_080136e0 - fault codes 5/6
            0x08013aecL,                // FUN_08013a70 - 12-bad-reading threshold
            0x08013b84L                 // FUN_08013b08 - different threshold/flag
        };
        int safetyOk = 0;
        for (long s : safetySites) {
            Instruction insn = getInstructionAt(toAddr(s));
            String mnem = insn == null ? "NULL" : insn.toString();
            boolean ok = mnem.contains("0x8019638") || mnem.contains("08019638");
            if (ok) safetyOk++;
            dumpInsn(ok ? "[SAFE-UNTOUCHED]" : "[!!!! UNEXPECTED CHANGE !!!!]", s);
        }
        println("Safety sites confirmed unchanged: " + safetyOk + " / " + safetySites.length);

        println("\n=== BOOT-LOGIC SITES in FUN_08064ede (expect: unchanged, bl FUN_08019638) ===");
        dumpInsn("[boot-logic A]", 0x08065166L);
        dumpInsn("[boot-logic B]", 0x080651ecL);

        println("\n=== VOLUME/MUTE FIX SITES (expect: unchanged, bl to volmute trampoline) ===");
        dumpInsn("[volmute site 1]", 0x0804ae70L);
        dumpInsn("[volmute site 2]", 0x0804ae8eL);

        println("\n=== FULL CALLER RE-SCAN of FUN_08019638 (post-patch, expect exactly 10 direct callers left) ===");
        ghidra.program.model.listing.Function shutdownFn = getFunctionAt(toAddr(0x08019638L));
        if (shutdownFn == null) {
            println("  [FUN_08019638 not found at expected address post-patch!]");
        } else {
            int count = 0;
            ghidra.program.model.symbol.ReferenceIterator refs =
                    currentProgram.getReferenceManager().getReferencesTo(shutdownFn.getEntryPoint());
            while (refs.hasNext()) {
                ghidra.program.model.symbol.Reference r = refs.next();
                println("  caller: " + r.getFromAddress());
                count++;
            }
            println("  TOTAL direct callers remaining: " + count + " (expect 10: all safety-critical)");
        }

        println("\nDONE_FINAL_VERIFY");
    }
}
