import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRPowerPath extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] targets = {"0x0804b090", "0x2001c030"};
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : targets) {
            Address target = currentProgram.getAddressFactory().getAddress(value);
            println("\n=== refs to " + target + " ===");
            for (Reference reference : getReferencesTo(target)) {
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
