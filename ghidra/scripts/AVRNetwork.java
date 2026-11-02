import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRNetwork extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] addresses = {
            "0x080bcfe4", "0x080bd280", "0x080bd288", "0x080c0678",
            "0x080c7110", "0x080be390", "0x080be85c", "0x080bf094",
            "0x080bf0b8", "0x080bfb2c", "0x080bfb4c", "0x080c05d0"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> decompiled = new HashSet<>();

        for (String value : addresses) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Data data = getDataAt(address);
            println("\n=== " + value + " data=" +
                (data == null ? "undefined" : data.getValue()) + " ===");
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println("ref=" + reference.getFromAddress() + " function=" +
                    (function == null ? "unresolved" :
                        function.getEntryPoint() + " " + function.getName()));
                if (function == null || !decompiled.add(function.getEntryPoint().toString())) {
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String code = result.getDecompiledFunction().getC();
                    println("--- " + function.getName() + " ---");
                    println(code.substring(0, Math.min(6000, code.length())));
                } else {
                    println("Decompilation incomplete: " + function.getName());
                }
            }
        }
        decompiler.dispose();
    }
}
