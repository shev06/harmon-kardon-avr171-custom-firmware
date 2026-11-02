import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRProtocolHandlers extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x08044f14", "0x08044fe2", "0x08047e4c", "0x080489ac"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : entries) {
            Function function = getFunctionAt(
                currentProgram.getAddressFactory().getAddress(value));
            if (function == null) {
                println("Unresolved function: " + value);
                continue;
            }
            if (printed.add(function.getEntryPoint().toString())) {
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                println("\n=== " + function.getEntryPoint() + " " +
                    function.getName() + " ===");
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    println(result.getDecompiledFunction().getC());
                } else {
                    println("Decompilation incomplete");
                }
            }
            println("--- callers of " + function.getEntryPoint() + " ---");
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
