import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRRequestPipeline extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x0804b1ee", "0x08048020", "0x08048884", "0x080488fc",
            "0x0804b208", "0x08048c98", "0x080489ac", "0x08047e4c",
            "0x08049d90", "0x08044dc4", "0x0804541c", "0x08077c44",
            "0x08062bf0", "0x08062c84", "0x08062ccc", "0x08062ce0",
            "0x080629fe", "0x08062ab2", "0x0804b20c", "0x0806299c",
            "0x080629e2", "0x08047d64", "0x080468f4", "0x08092e60",
            "0x0807ad66", "0x0807adfc", "0x0807ab88", "0x0807aba8",
            "0x0807ae8a", "0x0807b12e"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : entries) {
            Function function = getFunctionAt(
                currentProgram.getAddressFactory().getAddress(value));
            if (function == null) {
                println("\nUnresolved function: " + value);
                continue;
            }
            if (printed.add(function.getEntryPoint().toString())) {
                DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
                println("\n=== " + function.getEntryPoint() + " " +
                    function.getName() + " ===");
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    println(result.getDecompiledFunction().getC());
                } else {
                    println("Decompilation incomplete");
                }
            }
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
