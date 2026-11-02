import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

/** Finds callers of the confirmed flash erase/program/unlock/lock routines,
 *  across the whole image (not restricted to Function-wrapped code), to
 *  locate the higher-level update orchestrator and target address range. */
public class AVRFlashCallers extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] targets = {
            "0x0800ada4", "0x0800adba", "0x0800adcc", "0x0800ae4a", "0x0800aeaa",
            "0x0800af06", "0x0800af54"
        };
        for (String t : targets) {
            Address addr = currentProgram.getAddressFactory().getAddress(t);
            println("\n=== callers of " + t + " ===");
            boolean any = false;
            for (Reference ref : getReferencesTo(addr)) {
                any = true;
                Address from = ref.getFromAddress();
                Instruction ins = currentProgram.getListing().getInstructionAt(from);
                Function fn = getFunctionContaining(from);
                println("  " + from + " (" + (fn == null ? "no fn" : fn.getName()) + "): " +
                    (ins == null ? "?" : ins.toString()));
            }
            if (!any) {
                println("  (none found via reference manager)");
            }
        }
    }
}
