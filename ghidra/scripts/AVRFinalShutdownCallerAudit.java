import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;

// Exhaustive, final audit: every single XREF call to FUN_08019638 (the full
// hard-shutdown routine) firmware-wide, classified by exact address, so we
// can be certain we have found and accounted for every direct call site
// reachable from a power-down request, with zero remaining gaps.
public class AVRFinalShutdownCallerAudit extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address target = toAddr(0x08019638L);
        Function targetFn = getFunctionAt(target);
        println("=== EXHAUSTIVE CALLER AUDIT: " + targetFn.getName() + " @ " + targetFn.getEntryPoint() + " ===");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
        int count = 0;
        while (refs.hasNext()) {
            Reference r = refs.next();
            if (!r.getReferenceType().isCall()) continue;
            Address from = r.getFromAddress();
            Function callerFn = getFunctionContaining(from);
            Instruction insn = getInstructionAt(from);
            println("  [" + (++count) + "] call@" + from + ": " + insn
                    + "   [in " + (callerFn != null ? callerFn.getName() + "@" + callerFn.getEntryPoint() : "?") + "]");
        }
        println("Total call-type references to FUN_08019638: " + count);

        // Also check: does anything call FUN_08019638 indirectly (via function
        // pointer / computed branch) that a simple reference scan would miss?
        // Look for its address appearing as a raw literal-pool constant anywhere
        // (would indicate a function-pointer table entry or indirect call setup).
        println("\n=== Checking for FUN_08019638's address (0x08019638) appearing as a raw pool constant (possible indirect/function-pointer use) ===");
        ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
        int poolHits = 0;
        for (ghidra.program.model.mem.MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            for (long a = startOff; a + 4 <= endOff; a += 4) {
                try {
                    Address addr = toAddr(a);
                    int b0 = mem.getByte(addr) & 0xFF;
                    int b1 = mem.getByte(addr.add(1)) & 0xFF;
                    int b2 = mem.getByte(addr.add(2)) & 0xFF;
                    int b3 = mem.getByte(addr.add(3)) & 0xFF;
                    long val = (long)(b0 | (b1 << 8) | (b2 << 16)) | ((long)b3 << 24);
                    // Thumb function pointers have bit0 set (0x08019639)
                    if (val == 0x08019638L || val == 0x08019639L) {
                        println("  POOL CONSTANT at " + addr + " = 0x" + Long.toHexString(val));
                        poolHits++;
                    }
                } catch (Exception e) { /* skip */ }
            }
        }
        println("Total raw pool-constant hits: " + poolHits);
        println("\nDONE_FINAL_AUDIT");
    }
}
