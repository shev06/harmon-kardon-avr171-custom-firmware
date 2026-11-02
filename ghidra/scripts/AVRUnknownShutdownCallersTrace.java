import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;

// Decompile and find callers for the 5 previously-unexamined functions that
// directly call FUN_08019638 (full hard shutdown), to determine whether
// each is CEC/button-reachable (in scope) or a separate/safety mechanism
// (e.g. thermal/overcurrent protection) that must NOT be touched.
public class AVRUnknownShutdownCallersTrace extends ghidra.app.script.GhidraScript {
    private DecompInterface decomp;

    private void setupDecompiler() {
        decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(currentProgram);
    }

    private void decompileAndPrint(long addr, String label) throws Exception {
        Address a = toAddr(addr);
        Function fn = getFunctionAt(a);
        if (fn == null) {
            println(label + ": NO FUNCTION AT " + a);
            return;
        }
        println("=== DECOMPILE " + label + " : " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
        DecompileResults res = decomp.decompileFunction(fn, 120, monitor);
        if (res != null && res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("DECOMPILE FAILED: " + (res != null ? res.getErrorMessage() : "null result"));
        }
        // Callers
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        println("--- Callers of " + fn.getName() + " ---");
        int count = 0;
        while (refs.hasNext()) {
            Reference r = refs.next();
            if (!r.getReferenceType().isCall()) continue;
            Address from = r.getFromAddress();
            Function callerFn = getFunctionContaining(from);
            println("  called from " + from + " in " + (callerFn != null ? callerFn.getName() + "@" + callerFn.getEntryPoint() : "?"));
            count++;
        }
        println("  Total callers: " + count);
        println();
    }

    @Override
    public void run() throws Exception {
        setupDecompiler();
        decompileAndPrint(0x08013138, "FUN_08013138");
        decompileAndPrint(0x08013506, "FUN_08013506");
        decompileAndPrint(0x080136e0, "FUN_080136e0");
        decompileAndPrint(0x08013a70, "FUN_08013a70");
        decompileAndPrint(0x08013b08, "FUN_08013b08");
        println("\nDONE_UNKNOWN_CALLERS_TRACE");
    }
}
