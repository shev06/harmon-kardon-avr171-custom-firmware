import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.AddressRange;

// Prints every function as: FUNC <entry> <minAddr> <maxAddr> <name>  (hex, no 0x prefix).
// Used by the Python tooling to map any instruction address to its containing function.
// Usage: -postScript AVRFuncRanges.java
public class AVRFuncRanges extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int n = 0;
        while (it.hasNext()) {
            Function f = it.next();
            for (AddressRange r : f.getBody().getAddressRanges()) {
                println(String.format("FUNC %s %s %s %s", f.getEntryPoint(), r.getMinAddress(), r.getMaxAddress(), f.getName()));
            }
            n++;
        }
        println("FUNC_COUNT " + n);
    }
}
