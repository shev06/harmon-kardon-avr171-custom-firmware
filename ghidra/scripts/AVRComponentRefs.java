import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRComponentRefs extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] targets = {
            "0x080a0000", "0x080b0000", "0x080c0000", "0x080d0000",
            "0x08100000", "0x08100503", "0x08200000", "0x08300000",
            "0x08400000", "0x08500000"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : targets) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            println("\n=== refs " + address + " ===");
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + "\t" +
                    reference.getReferenceType() + "\t" +
                    (function == null ? "no function" :
                        function.getEntryPoint() + " " + function.getName()));
                if (function != null && printed.add(function.getEntryPoint().toString())) {
                    DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                    println("\n--- " + function.getEntryPoint() + " " +
                        function.getName() + " ---");
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        println(result.getDecompiledFunction().getC());
                    } else {
                        println("Decompilation incomplete");
                    }
                }
            }
        }
        decompiler.dispose();
    }
}
