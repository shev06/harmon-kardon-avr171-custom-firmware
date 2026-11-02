import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRBusRx extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        String[] entries = {
            "0x08047e4c", "0x080480dc", "0x080489ac", "0x08048c98"
        };
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionAt(address);
            if (function == null) {
                println("Unresolved function: " + value);
                continue;
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            println("\n=== " + function.getEntryPoint() + " " + function.getName() + " ===");
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                String code = result.getDecompiledFunction().getC();
                println(code.substring(0, Math.min(6500, code.length())));
            } else {
                println("Decompilation incomplete");
            }
            println("--- callers ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                if (caller != null) {
                    println(reference.getFromAddress() + " <- " +
                        caller.getEntryPoint() + " " + caller.getName());
                }
            }
        }
        decompiler.dispose();
    }
}
