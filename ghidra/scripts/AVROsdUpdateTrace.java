import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.LinkedHashSet;
import java.util.Set;

public class AVROsdUpdateTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x08085686", "0x0808a8ac", "0x080963de", "0x080963ca",
            "0x0809653e", "0x0809672c", "0x08068eac", "0x08070116"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<Address> seen = new LinkedHashSet<>();
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionContaining(address);
            if (function == null || !seen.add(function.getEntryPoint())) {
                continue;
            }
            println("\n=== " + function.getEntryPoint() + " " + function.getName() + " ===");
            DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
            println(result.decompileCompleted() && result.getDecompiledFunction() != null
                ? result.getDecompiledFunction().getC()
                : "Decompilation incomplete: " + result.getErrorMessage());
            println("--- callers ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
                    (caller == null ? "no function" :
                        caller.getEntryPoint() + " " + caller.getName()));
            }
        }
        decompiler.dispose();
    }
}
