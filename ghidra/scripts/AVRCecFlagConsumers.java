import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRCecFlagConsumers extends ghidra.app.script.GhidraScript {

    private DecompInterface decompiler;

    @Override
    public void run() throws Exception {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        Address litPool = currentProgram.getAddressFactory().getAddress("0x0808ca4c");

        println("##### All code that loads the literal pool entry at 0x0808ca4c (the CEC state struct base) #####");
        Set<String> fnsSeen = new HashSet<>();
        for (Reference ref : getReferencesTo(litPool)) {
            Address from = ref.getFromAddress();
            Instruction instr = getInstructionAt(from);
            Function fn = getFunctionContaining(from);
            println("  ref at " + from + " (" + (instr != null ? instr.toString() : "?") + ") in function "
                    + (fn != null ? fn.getName() + "@" + fn.getEntryPoint() : "UNKNOWN"));

            // look at the next ~6 instructions after this load for an access to offset 0xa
            Address a = from;
            for (int i = 0; i < 6 && a != null; i++) {
                Instruction nextI = getInstructionAt(a);
                if (nextI == null) break;
                String s = nextI.toString();
                if (s.contains(",#0xa]") || s.contains("#0xa]")) {
                    println("     >>> OFFSET 0xa ACCESS nearby at " + a + ": " + s);
                }
                a = nextI.getFallThrough();
            }

            if (fn != null) {
                String key = fn.getEntryPoint().toString();
                if (!fnsSeen.contains(key)) {
                    fnsSeen.add(key);
                }
            }
        }

        println("\n##### Distinct functions referencing this struct base, decompiled: #####");
        for (String addrStr : fnsSeen) {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function fn = getFunctionAt(addr);
            if (fn == null) continue;
            println("\n=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
            DecompileResults result = decompiler.decompileFunction(fn, 60, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("Decompilation incomplete");
            }
        }

        decompiler.dispose();
    }
}
