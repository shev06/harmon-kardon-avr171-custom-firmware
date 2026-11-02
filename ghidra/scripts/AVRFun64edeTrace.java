import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;

public class AVRFun64edeTrace extends ghidra.app.script.GhidraScript {
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
    }

    private void listCallers(long addr, String label) throws Exception {
        Address a = toAddr(addr);
        Function fn = getFunctionAt(a);
        if (fn == null) {
            println(label + ": NO FUNCTION AT " + a);
            return;
        }
        println("=== CALLERS of " + label + " (" + fn.getName() + ") ===");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
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
    }

    @Override
    public void run() throws Exception {
        setupDecompiler();
        decompileAndPrint(0x08064ede, "FUN_08064ede");
        listCallers(0x08064ede, "FUN_08064ede");
        println("\nDONE_64EDE_TRACE");
    }
}
