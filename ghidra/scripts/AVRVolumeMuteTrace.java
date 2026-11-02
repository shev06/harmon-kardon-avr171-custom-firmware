// Decompile FUN_0802d174 (CEC audio-status / real volume+mute source), trace the
// dispatcher's volume/mute query-status branches precisely, and search for a
// reusable decimal-to-ASCII (itoa) helper via the classic /10 reciprocal-multiply
// magic constant (0x66666667) so we know whether we can reuse an existing
// number-formatting routine instead of writing one from scratch.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

public class AVRVolumeMuteTrace extends GhidraScript {
    DecompInterface decomp;

    private void decompileFn(String label, long addr) throws Exception {
        Address a = toAddr(addr);
        Function f = getFunctionAt(a);
        println("=== " + label + " @ " + a + " func=" + f);
        if (f == null) { println("  NOT a function here"); return; }
        DecompileResults res = decomp.decompileFunction(f, 60, monitor);
        if (res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("  decompile failed: " + res.getErrorMessage());
        }
    }

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.openProgram(currentProgram);

        decompileFn("FUN_0802d174 (CEC audio-status / real vol+mute source)", 0x0802d174);

        println("\n=== Disassembly around dispatcher volume/mute query-status branches ===");
        Listing listing = currentProgram.getListing();
        long[] ranges = { 0x0804ae50L, 0x0804aea0L };
        for (long a = ranges[0]; a < ranges[1]; ) {
            Instruction ins = listing.getInstructionAt(toAddr(a));
            if (ins == null) { a += 2; continue; }
            println(String.format("%08x  %-40s", a, ins.toString()));
            a += ins.getLength();
        }

        println("\n=== Searching whole image for /10 reciprocal-multiply magic constant (0x66666667) ===");
        Memory mem = currentProgram.getMemory();
        byte[] pattern = new byte[]{ 0x67, 0x66, 0x66, 0x66 }; // little-endian 0x66666667
        Address start = currentProgram.getMinAddress();
        Address found = start;
        int count = 0;
        while (true) {
            found = mem.findBytes(found, pattern, null, true, monitor);
            if (found == null || count > 40) break;
            Function fn = getFunctionContaining(found);
            println("  hit @ " + found + "  inFunction=" + (fn != null ? fn.getName() + "@" + fn.getEntryPoint() : "none"));
            try { found = found.add(1); } catch (Exception e) { break; }
            count++;
        }

        println("\n=== Callers of FUN_0802d174 ===");
        Function target = getFunctionAt(toAddr(0x0802d174));
        if (target != null) {
            for (Address xref : target.getSymbol().getReferences() != null ? new Address[0] : new Address[0]) {}
            for (var ref : getReferencesTo(target.getEntryPoint())) {
                println("  called from " + ref.getFromAddress() + " type=" + ref.getReferenceType());
            }
        }

        decomp.dispose();
        println("\nDONE");
    }
}
