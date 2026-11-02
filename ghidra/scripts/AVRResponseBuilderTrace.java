import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRResponseBuilderTrace extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void decompileAt(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("=== " + label + " (" + addrStr + ") ===");
        if (f == null) {
            println("[no function containing " + addrStr + "]");
            return;
        }
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        println("function: " + f.getEntryPoint() + " body ends " + f.getBody().getMaxAddress());
        if (r.decompileCompleted()) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("[decompile failed: " + r.getErrorMessage() + "]");
        }
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        // 1) The response-builder function itself.
        decompileAt("FUN_08044dc4 (response builder)", "0x08044dc4");

        // 2) The function called right after it in the query-status/power branch --
        //    this is what actually sends the built buffer out over the socket.
        decompileAt("FUN_0804541c (post-build send?)", "0x0804541c");

        // 3) Everything that reads or writes the power-state byte at DAT_0804b090's
        //    target address -- resolve the literal pool pointer first.
        Address lit = currentProgram.getAddressFactory().getAddress("0x0804b090");
        int ptrVal = getInt(lit);
        Address stateAddr = toAddr(ptrVal & 0xFFFFFFFFL);
        println("\n=== DAT_0804b090 literal-pool resolves to RAM address " + stateAddr + " ===");

        println("\n=== All references to " + stateAddr + " ===");
        java.util.Set<String> done = new java.util.HashSet<>();
        for (Reference ref : getReferencesTo(stateAddr)) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " " + ref.getReferenceType() + " in " +
                (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }
        for (Reference ref : getReferencesTo(stateAddr)) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            if (cf != null && done.add(cf.getEntryPoint().toString())) {
                DecompileResults r = decompiler.decompileFunction(cf, 60, monitor);
                println("--- " + cf.getEntryPoint() + " " + cf.getName() + " ---");
                if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            }
        }

        decompiler.dispose();
    }
}
