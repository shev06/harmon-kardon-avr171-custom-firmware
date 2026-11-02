import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.address.Address;

// Finds WHO calls FUN_080192e2 / FUN_08019272 / FUN_08019378 / FUN_08060c64
// (the piece we never actually traced -- we only looked at what these call,
// not what calls them), and fully decompiles FUN_08019378 (previously only
// identified as "a writer of the countdown cell", never examined in full).
public class AVRPowerCallerUpTrace extends ghidra.app.script.GhidraScript {
    private DecompInterface decompiler;

    private void listCallers(String label, long addr) {
        println("--- Callers of " + label + " (0x" + Long.toHexString(addr) + ") ---");
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) { println("  [no function at this address]"); return; }
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int count = 0;
        while (refs.hasNext()) {
            Reference r = refs.next();
            if (!r.getReferenceType().isCall()) continue;
            Address from = r.getFromAddress();
            Function caller = getFunctionContaining(from);
            println("  called from " + from + " inside " + (caller != null ? caller.getName() + "@" + caller.getEntryPoint() : "[unknown]"));
            count++;
        }
        println("  total call references: " + count);
    }

    @Override
    public void run() throws Exception {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        listCallers("FUN_080192e2", 0x080192e2L);
        listCallers("FUN_08019272", 0x08019272L);
        listCallers("FUN_08019378", 0x08019378L);
        listCallers("FUN_08060c64", 0x08060c64L);

        println("\n=== Full decompile of FUN_08019378 (never fully examined before) ===");
        Function f = getFunctionAt(toAddr(0x08019378L));
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "[decompile failed]");

        println("\n=== Full decompile of FUN_08060c64 (the message-trigger function) ===");
        Function f2 = getFunctionAt(toAddr(0x08060c64L));
        DecompileResults r2 = decompiler.decompileFunction(f2, 60, monitor);
        println(r2.decompileCompleted() ? r2.getDecompiledFunction().getC() : "[decompile failed]");

        decompiler.dispose();
        println("\nDONE");
    }
}
