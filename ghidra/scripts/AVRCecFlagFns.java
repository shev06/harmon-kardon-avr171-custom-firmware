import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class AVRCecFlagFns extends ghidra.app.script.GhidraScript {

    private DecompInterface decompiler;

    private void dump(String addrHex) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrHex);
        Function fn = getFunctionAt(addr);
        if (fn == null) {
            println(addrHex + ": NO FUNCTION FOUND");
            return;
        }
        println("\n=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
        DecompileResults result = decompiler.decompileFunction(fn, 60, monitor);
        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
            println(result.getDecompiledFunction().getC());
        } else {
            println("Decompilation incomplete");
        }
    }

    @Override
    public void run() throws Exception {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        String[] targets = {
            "0x08062e20", "0x08092fd8", "0x0808e51a",
            "0x080930ca", "0x0807c2f4", "0x0808e268"
        };
        for (String t : targets) {
            dump(t);
        }

        decompiler.dispose();
    }
}
