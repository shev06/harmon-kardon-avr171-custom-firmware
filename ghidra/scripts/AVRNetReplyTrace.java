import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRNetReplyTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        String[] entries = {
            "0x08047e4c", "0x08012f6c", "0x0801302c",
            "0x0804b208", "0x08048c98", "0x08048610",
            "0x080468f4", "0x08047700", "0x0803ca70", "0x0806e84c",
            "0x08062bf0", "0x08062c84"
        };
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionAt(address);
            if (function == null) {
                println("Unresolved function: " + value);
                continue;
            }
            if (printed.add(function.getEntryPoint().toString())) {
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                println("\n=== " + function.getEntryPoint() + " " + function.getName() + " ===");
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String code = result.getDecompiledFunction().getC();
                    println(code.substring(0, Math.min(6000, code.length())));
                } else {
                    println("Decompilation incomplete");
                }
            }
            println("--- references to " + function.getEntryPoint() + " ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
                    (caller == null ? "unresolved" :
                        caller.getEntryPoint() + " " + caller.getName()));
            }
        }
        decompiler.dispose();
    }
}
