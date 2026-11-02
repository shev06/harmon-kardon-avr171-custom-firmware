import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRStringXrefs extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] values = {
            "0x080bfb6c", "0x080c0694", "0x080c1340",
            "0x080c27ac", "0x080c27fc", "0x080c2838", "0x080c284c",
            "0x080c2874", "0x080c289c", "0x080c2b80", "0x080c2b94"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : values) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            println("\n=== references to " + address + " ===");
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
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
