public class AVRMainLoopTiming extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
        decompiler.openProgram(currentProgram);
        ghidra.program.model.listing.Function f = getFunctionAt(toAddr(0x0801074cL));
        println("=== Decompile FUN_0801074c (caller of tick dispatcher FUN_08011910) ===");
        if (f != null) {
            ghidra.app.decompiler.DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
            if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            else println("[failed: " + r.getErrorMessage() + "]");
        }
        decompiler.dispose();
        println("DONE");
    }
}
