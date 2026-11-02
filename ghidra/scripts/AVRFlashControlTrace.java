import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.LinkedHashSet;
import java.util.Set;

public class AVRFlashControlTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x0808bb98", "0x0808bbdc", "0x0808bc68", "0x0808bc80", "0x0808bd00",
            "0x0800af00", "0x08006980", "0x08008040"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<Address> seen = new LinkedHashSet<>();
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionContaining(address);
            if (function == null || !seen.add(function.getEntryPoint())) {
                println("\n=== " + address + ": no containing function ===");
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
