import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRSubsystemTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        String[] entries = {
            "0x08044dc4", "0x08049d90", "0x0804541c",
            "0x0804b304", "0x0804b4b2", "0x0804b56e",
            "0x0804cd1c", "0x08048610"
        };
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionContaining(address);
            if (function == null) {
                println("Unresolved function containing " + value);
                continue;
            }
            String key = function.getEntryPoint().toString();
            if (printed.add(key)) {
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                println("\n=== " + key + " " + function.getName() + " ===");
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String code = result.getDecompiledFunction().getC();
                    println(code.substring(0, Math.min(9000, code.length())));
                } else {
                    println("Decompilation incomplete");
                }
            }
            println("--- callers of " + key + " ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                if (caller != null) {
                    println(reference.getFromAddress() + " <- " + caller.getEntryPoint() +
                        " " + caller.getName());
                }
            }
        }
        decompiler.dispose();
    }
}
