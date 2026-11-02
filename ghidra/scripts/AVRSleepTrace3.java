import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class AVRSleepTrace3 extends ghidra.app.script.GhidraScript {
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
        decompileAt("pre-sleep prep FUN_08014aa0", "0x08014aa0");
        decompileAt("post-wake resume FUN_08014bec", "0x08014bec");
        decompileAt("post-wake clock-reinit FUN_080657ba", "0x080657ba");
        decompileAt("pre-sleep CEC-send FUN_0804b20c", "0x0804b20c");
        // Callers of the outer sleep-entry function to see what triggers it
        println("\n=== Callers of FUN_08014a40 (outer STOP-mode entry) ===");
        Address target = currentProgram.getAddressFactory().getAddress("0x08014a40");
        for (ghidra.program.model.symbol.Reference ref : getReferencesTo(target)) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " in " + (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }
        decompiler.dispose();
    }
}
