public class AVRAutoOffDecompile extends ghidra.app.script.GhidraScript {
    void dump(String label, long addr) throws Exception {
        ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
        decompiler.openProgram(currentProgram);
        ghidra.program.model.listing.Function f = getFunctionAt(toAddr(addr));
        println("\n=== " + label + " (" + f + ") ===");
        if (f != null) {
            ghidra.app.decompiler.DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
            if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            else println("[failed: " + r.getErrorMessage() + "]");
        } else {
            println("[not found]");
        }
        decompiler.dispose();
    }

    @Override
    public void run() throws Exception {
        dump("FUN_0801074c FULL (tick-driver, reads/writes 0x2001bfd8)", 0x0801074cL);
        dump("FUN_0805479c (AUTO OFF menu string table user)", 0x0805479cL);
        dump("FUN_08012e78 (another 0x2001bfd8 writer)", 0x08012e78L);
        println("\nDONE");
    }
}
