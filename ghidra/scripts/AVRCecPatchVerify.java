import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

// Independent re-validation: decompile the patched FUN_0809b3fc (and its new
// trampoline) from a completely fresh import of the patched file, to confirm
// the fix reads correctly post-patch and introduces no unintended side effects.
public class AVRCecPatchVerify extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();
    void dump(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("[no function - raw region, expected for trampoline]"); return; }
        println("function: " + f.getEntryPoint() + " - " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("[failed: " + r.getErrorMessage() + "]");
    }
    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);
        dump("Patched CEC RX handler", "0x0809b3fc");
        decompiler.dispose();
    }
}
