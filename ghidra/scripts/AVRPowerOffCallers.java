import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRPowerOffCallers extends ghidra.app.script.GhidraScript {

    private void printCallers(String label, String addrHex) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrHex);
        Function fn = getFunctionAt(addr);
        if (fn == null) {
            println(label + " @ " + addrHex + ": NO FUNCTION");
            return;
        }
        println("\n=== Callers of " + label + " (" + fn.getName() + " @ " + fn.getEntryPoint() + ") ===");
        Reference[] refs = getReferencesTo(fn.getEntryPoint());
        Set<String> seen = new HashSet<>();
        for (Reference ref : refs) {
            Address from = ref.getFromAddress();
            Function caller = getFunctionContaining(from);
            String callerName = caller == null ? "???" : caller.getName() + "@" + caller.getEntryPoint();
            String key = from + "->" + callerName;
            if (seen.add(key)) {
                println("  " + from + " (in " + callerName + ")");
            }
        }
    }

    private void findReadsOf(String label, String addrHex) throws Exception {
        Address target = currentProgram.getAddressFactory().getAddress(addrHex);
        println("\n=== Instructions referencing RAM pointer literal that resolves to " + label + " (" + addrHex + ") ===");
        // find literal pool entries holding this address, then find xrefs to those entries
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            Object val = data.getValue();
            if (val instanceof Address && ((Address) val).equals(target)) {
                for (Reference ref : getReferencesTo(data.getAddress())) {
                    Address from = ref.getFromAddress();
                    Instruction instr = getInstructionAt(from);
                    Function caller = getFunctionContaining(from);
                    String callerName = caller == null ? "???" : caller.getName() + "@" + caller.getEntryPoint();
                    println("  " + from + " [" + (instr == null ? "?" : instr.toString()) + "] in " + callerName);
                }
            }
        }
    }

    @Override
    public void run() throws Exception {
        printCallers("power-on handler FUN_080192ce", "0x080192ce");
        printCallers("power-off handler FUN_080192e2", "0x080192e2");
        printCallers("power-toggle handler FUN_08019272", "0x08019272");
        printCallers("full-shutdown FUN_08019638", "0x08019638");

        findReadsOf("fade target DAT_08019c6c", "0x08019c6c");
        findReadsOf("fade counter DAT_08019c70", "0x08019c70");
    }
}
