import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

// Determines whether the normal cold-boot path unconditionally re-checks for a
// USB update file BEFORE jumping into the application (via FUN_080062f0), or
// whether reaching "look for a USB update" requires the application's own
// running menu system (System Setup -> Software Update). This is the single
// fact that decides whether a bricked/hung application is still recoverable
// via plain USB (no SWD/JTAG needed) or not.
public class AVRBootRecoveryTrace extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void decompileAt(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("[no function]"); return; }
        println("function: " + f.getEntryPoint() + " body ends " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("[decompile failed: " + r.getErrorMessage() + "]");
    }

    void callersOf(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        println("\n=== Callers of " + label + " (" + addrStr + ") ===");
        for (Reference ref : getReferencesTo(a)) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            println("  " + ref.getFromAddress() + " " + ref.getReferenceType() +
                " in " + (caller == null ? "?" : caller.getEntryPoint() + " " + caller.getName()));
        }
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        // Reset handler / earliest boot entry (bootloader vector table at 0x08000000)
        decompileAt("Bootloader reset handler", "0x08000000");

        // The 4 distinct non-write-loop callers of the jump trampoline
        decompileAt("FUN_0800563a", "0x0800563a");
        decompileAt("FUN_08005be4", "0x08005be4");
        decompileAt("FUN_08005d5c", "0x08005d5c");
        decompileAt("FUN_08007ac4", "0x08007ac4");

        // Who calls each of THOSE (one level further back toward reset)?
        callersOf("FUN_0800563a", "0x0800563a");
        callersOf("FUN_08005be4", "0x08005be4");
        callersOf("FUN_08005d5c", "0x08005d5c");
        callersOf("FUN_08007ac4", "0x08007ac4");

        decompiler.dispose();
    }
}
