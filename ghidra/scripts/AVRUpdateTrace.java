import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRUpdateTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] functions = {
            "0x08048610", "0x08048c98", "0x0805160c", "0x080bab08",
            "0x08051efc", "0x08052b2c"
        };
        String[] strings = {
            "0x0800d158", "0x0800d290", "0x0800d348", "0x080bfb6c",
            "0x080c0694", "0x080c1340", "0x080c2b80", "0x080c2b94"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();

        for (String value : functions) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionContaining(address);
            println("\n=== function containing " + address + ": " +
                (function == null ? "none" : function.getEntryPoint() + " " +
                    function.getName()) + " ===");
            if (function == null || !printed.add(function.getEntryPoint().toString())) {
                continue;
            }
            DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("Decompilation incomplete: " + result.getErrorMessage());
            }
            println("--- callers ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
                    (caller == null ? "no function" :
                        caller.getEntryPoint() + " " + caller.getName()));
            }
        }

        for (String value : strings) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            println("\n=== references to string/data " + address + " ===");
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
                    (function == null ? "no function" :
                        function.getEntryPoint() + " " + function.getName()));
            }
        }
        decompiler.dispose();
    }
}
