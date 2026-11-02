import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

// Independent re-validation: decompile the patched FUN_08064de8 (the sole
// STM32 STOP-mode sleep-entry routine) from a completely fresh import of the
// patched file, to confirm the WFI/WFE->NOP fix reads correctly post-patch
// and introduces no unintended side effects (e.g. no leftover dead branch,
// no corrupted literal pool, no change to function boundaries).
public class AVRSleepPatchVerify extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();
    void dump(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("[no function at this address]"); return; }
        println("function: " + f.getEntryPoint() + " - " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("[failed: " + r.getErrorMessage() + "]");
    }
    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);
        dump("Patched STOP-mode sleep-entry routine", "0x08064de8");
        decompiler.dispose();
    }
}
