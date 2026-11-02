import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class AVRSleepTrace4 extends ghidra.app.script.GhidraScript {
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
        decompileAt("caller A FUN_0801074c", "0x0801074c");
        decompileAt("caller B FUN_08012720", "0x08012720");

        // Also find callers of those two, to climb toward the top-level trigger (button/menu/timer)
        println("\n=== Callers of FUN_0801074c ===");
        for (ghidra.program.model.symbol.Reference ref : getReferencesTo(currentProgram.getAddressFactory().getAddress("0x0801074c"))) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " in " + (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }
        println("\n=== Callers of FUN_08012720 ===");
        for (ghidra.program.model.symbol.Reference ref : getReferencesTo(currentProgram.getAddressFactory().getAddress("0x08012720"))) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " in " + (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }
        decompiler.dispose();
    }
}
