import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRNetSocketTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x080489ac", "0x08047e4c", "0x080480dc",
            "0x08045448", "0x08045460", "0x0804548c",
            "0x08062ab2", "0x080629fe", "0x080629e2",
            "0x08062a5c", "0x08062ccc", "0x08062ce0"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionAt(address);
            if (function == null) {
                println("Unresolved function: " + value);
                continue;
            }
            if (printed.add(function.getEntryPoint().toString())) {
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
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
