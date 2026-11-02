import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class AVRVolMuteVerify extends GhidraScript {
    DecompInterface decomp;

    private void decompileFn(String label, long addr) throws Exception {
        Address a = toAddr(addr);
        Function f = getFunctionAt(a);
        if (f == null) {
            // force-disassemble + create function since fresh import has no analysis yet
            disassemble(a);
            f = createFunction(a, "FN_" + Long.toHexString(addr));
        }
        println("=== " + label + " @ " + a + " func=" + f);
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

        // Disassemble + decompile the main dispatcher function containing the patched branches
        disassemble(toAddr(0x0804ad00L));
        Function dispatcherFn = getFunctionContaining(toAddr(0x0804ae70L));
        if (dispatcherFn == null) {
            dispatcherFn = createFunction(toAddr(0x0804ad00L), "FUN_dispatcher");
        }
        println("=== Dispatcher function @ " + dispatcherFn.getEntryPoint() + " ===");
        DecompileResults res = decomp.decompileFunction(dispatcherFn, 60, monitor);
        if (res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("FAILED: " + res.getErrorMessage());
        }

        decompileFn("Volume trampoline", 0x080c8cd8L);
        decompileFn("Mute trampoline", 0x080c8d06L);

        println("\n=== Raw disassembly: volume trampoline ===");
        Listing listing = currentProgram.getListing();
        for (long addr = 0x080c8cd8L; addr < 0x080c8d06L; ) {
            Instruction ins = listing.getInstructionAt(toAddr(addr));
            if (ins == null) { addr += 2; continue; }
            println(String.format("%08x  %s", addr, ins.toString()));
            addr += ins.getLength();
        }
        println("\n=== Raw disassembly: mute trampoline ===");
        for (long addr = 0x080c8d06L; addr < 0x080c8d3cL; ) {
            Instruction ins = listing.getInstructionAt(toAddr(addr));
            if (ins == null) { addr += 2; continue; }
            println(String.format("%08x  %s", addr, ins.toString()));
            addr += ins.getLength();
        }

        println("\n=== Spot-check string table entries (0, 1, 50, 99, 100) ===");
        int[] pcts = {0, 1, 50, 99, 100};
        for (int p : pcts) {
            long tableEntryAddr = 0x080c8b44L + (p * 4);
            int strAddr = currentProgram.getMemory().getInt(toAddr(tableEntryAddr));
            byte[] buf = new byte[4];
            currentProgram.getMemory().getBytes(toAddr(strAddr & 0xFFFFFFFEL), buf);
            StringBuilder sb = new StringBuilder();
            for (byte b : buf) { if (b == 0) break; sb.append((char) b); }
            println("  percent=" + p + " -> table[" + p + "]=0x" + Integer.toHexString(strAddr) + " -> \"" + sb + "\"");
        }

        decomp.dispose();
        println("\nDONE");
    }
}
