import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRSleepTrace6 extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();
    void decompileAt(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("no function"); return; }
        println("function: " + f.getEntryPoint() + " body ends " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("decompile incomplete");
    }
    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);
        decompileAt("FUN_08010184 (caller of main tick fn)", "0x08010184");
        println("\n=== Callers of FUN_08010184 ===");
        for (Reference ref : getReferencesTo(currentProgram.getAddressFactory().getAddress("0x08010184"))) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " in " + (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }
        // Check if there's a SysTick handler / delay call inside FUN_08010184 by looking for known timer-ish function names
        decompileAt("FUN_0802da98 (called after countdown=7 set at 0x080b9984)", "0x0802da98");
        decompiler.dispose();
    }
}
