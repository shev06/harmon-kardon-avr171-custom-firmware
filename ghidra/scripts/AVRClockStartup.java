import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRClockStartup extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x08005500", "0x0800595c", "0x08005976", "0x08005a40",
            "0x08005a6e", "0x080057b4", "0x08005588", "0x080081b0",
            "0x080081ee"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            disassemble(address);
            if (getFunctionAt(address) == null) {
                createFunction(address, null);
            }
        };
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionContaining(address);
            println("\n=== " + address + " => " +
                (function == null ? "no function" :
                    function.getEntryPoint() + " " + function.getName()) + " ===");
            if (function == null) {
                continue;
            }
            DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("Decompilation incomplete: " + result.getErrorMessage());
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
