import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRNetFlow extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();

        String[] entries = {"0x08044dc4", "0x0804541c", "0x08049d90"};
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionAt(address);
            if (function == null) {
                println("Unresolved function: " + value);
                continue;
            }
            printFunction(decompiler, function, 10000, printed);
            println("--- callers of " + function.getEntryPoint() + " ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                if (caller != null) {
                    println("call from " + reference.getFromAddress() + " in " +
                        caller.getEntryPoint() + " " + caller.getName());
                    if (caller.getEntryPoint().getOffset() != function.getEntryPoint().getOffset()) {
                        printFunction(decompiler, caller, 7000, printed);
                    }
                }
            }
        }
        decompiler.dispose();
    }

    private void printFunction(DecompInterface decompiler, Function function,
            int limit, Set<String> printed) {
        if (!printed.add(function.getEntryPoint().toString())) {
            return;
        }
        DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
        println("\n=== " + function.getEntryPoint() + " " + function.getName() + " ===");
        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
            String code = result.getDecompiledFunction().getC();
            println(code.substring(0, Math.min(limit, code.length())));
        } else {
            println("Decompilation incomplete");
        }
    }
}
