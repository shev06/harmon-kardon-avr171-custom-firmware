import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRStatusStrings extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] addresses = {
            "0x080c41d8", "0x080c41ec", "0x080c4200", "0x080c428c",
            "0x080c42b4", "0x080c35a8", "0x080c3670", "0x080c261c"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : addresses) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Data data = getDataAt(address);
            println("\n=== " + value + " " +
                (data == null ? "undefined" : data.getValue()) + " ===");
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println("ref " + reference.getFromAddress() + " function=" +
                    (function == null ? "unresolved" : function.getEntryPoint() + " " + function.getName()));
                if (function == null || !printed.add(function.getEntryPoint().toString())) {
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String code = result.getDecompiledFunction().getC();
                    println(code.substring(0, Math.min(3500, code.length())));
                }
            }
        }
        decompiler.dispose();
    }
}
