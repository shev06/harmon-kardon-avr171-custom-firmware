import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRStartupHelpers extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x08002fe2", "0x08003010", "0x08003030", "0x08003086",
            "0x0800309c", "0x080030ee", "0x08003110", "0x0800314c",
            "0x0800d10c", "0x0800d188"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionContaining(address);
            println("\n=== " + address + " => " +
                (function == null ? "no function" :
                    function.getEntryPoint() + " " + function.getName()) + " ===");
            if (function == null) {
                continue;
            }
            DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("Decompilation incomplete: " + result.getErrorMessage());
            }
            println("--- direct callers ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
                    (caller == null ? "no function" :
                        caller.getEntryPoint() + " " + caller.getName()));
            }
        }
        decompiler.dispose();
    }
}
