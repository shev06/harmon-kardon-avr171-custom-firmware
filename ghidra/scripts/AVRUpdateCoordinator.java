import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.LinkedHashSet;
import java.util.Set;

public class AVRUpdateCoordinator extends ghidra.app.script.GhidraScript {
    private void printFunction(DecompInterface decompiler, Function function,
            Set<Address> seen) throws Exception {
        if (function == null || !seen.add(function.getEntryPoint())) {
            return;
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

    @Override
    public void run() throws Exception {
        String[] updateStrings = {
            "0x080be004", "0x080be0f4", "0x080be72c", "0x080c1340",
            "0x080c2b80", "0x080c2b94"
        };
        String[] entryPoints = {
            "0x08052b2c", "0x0805160c", "0x08051efc", "0x080bab08"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<Address> seen = new LinkedHashSet<>();
        for (String value : updateStrings) {
            Address string = currentProgram.getAddressFactory().getAddress(value);
            println("\n=== references to " + string + " ===");
            for (Reference reference : getReferencesTo(string)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
                    (function == null ? "no function" :
                        function.getEntryPoint() + " " + function.getName()));
                printFunction(decompiler, function, seen);
            }
        }
        for (String value : entryPoints) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            disassemble(address);
            if (getFunctionAt(address) == null) {
                createFunction(address, null);
            }
            printFunction(decompiler, getFunctionContaining(address), seen);
        }
        decompiler.dispose();
    }
}
