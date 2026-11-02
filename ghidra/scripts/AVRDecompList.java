import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;

// Generic: decompile every function whose entry address is passed as a script
// argument (hex, with or without 0x). Usage: -postScript AVRDecompList.java 08011910 0802d230 ...
public class AVRDecompList extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        String[] args = getScriptArgs();
        for (String a : args) {
            long addr = Long.parseLong(a.replace("0x", ""), 16);
            Function f = getFunctionAt(toAddr(addr));
            if (f == null) f = getFunctionContaining(toAddr(addr));
            println("\n################ " + a + " ################");
            if (f == null) { println("[no function at " + a + "]"); continue; }
            println("// function " + f.getName() + " entry=" + f.getEntryPoint() + " body=" + f.getBody());
            DecompileResults r = decompiler.decompileFunction(f, 120, monitor);
            println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "[decompile failed: " + r.getErrorMessage() + "]");
        }
        decompiler.dispose();
        println("\nDONE_DECOMP_LIST");
    }
}
