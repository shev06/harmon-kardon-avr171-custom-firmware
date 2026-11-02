import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRNetStatePath extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        String[] entries = {
            "0x0804541c", "0x08045448", "0x08045460", "0x0804548c",
            "0x08062bf0", "0x08062c84", "0x080925bc",
            "0x080928e0", "0x08092e60", "0x08092a38"
        };
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionAt(address);
            if (function == null) {
                println("Unresolved function: " + value);
                continue;
            }
            printFunction(decompiler, function, printed);
            println("--- references to " + function.getEntryPoint() + " ---");
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

    private void printFunction(DecompInterface decompiler, Function function,
            Set<String> printed) {
        if (!printed.add(function.getEntryPoint().toString())) {
            return;
        }
        DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
        println("\n=== " + function.getEntryPoint() + " " + function.getName() + " ===");
        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
            String code = result.getDecompiledFunction().getC();
            println(code.substring(0, Math.min(5000, code.length())));
        } else {
            println("Decompilation incomplete");
        }
    }
}
