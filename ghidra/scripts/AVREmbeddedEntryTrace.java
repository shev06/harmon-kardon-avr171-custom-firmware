import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVREmbeddedEntryTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {"0x080c6f2c", "0x080c7578", "0x080c2078"};
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            disassemble(address);
            if (getFunctionAt(address) == null) {
                createFunction(address, null);
            }
            Function function = getFunctionContaining(address);
            println("\n=== " + address + " => " +
                (function == null ? "no function" :
                    function.getEntryPoint() + " " + function.getName()) + " ===");
            if (function != null) {
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
        }
        decompiler.dispose();
    }
}
