import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRCecFlagConsumers2 extends ghidra.app.script.GhidraScript {

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Address litSlot = currentProgram.getAddressFactory().getAddress("0x0808ca4c");

        // Dereference the known literal slot to get the actual RAM struct base value.
        int structBase = mem.getInt(litSlot);
        println("Struct base value (from 0x0808ca4c) = 0x" + Integer.toHexString(structBase));

        // Now scan ALL defined data in the program for other 4-byte occurrences of this same value
        // (other literal-pool copies elsewhere in flash, out of PC-relative range of 0808ca4c).
        println("\n##### Scanning for other literal-pool copies of this same struct-base value #####");
        Set<String> otherSlots = new HashSet<>();
        var dataIter = currentProgram.getListing().getDefinedData(true);
        int count = 0;
        while (dataIter.hasNext()) {
            Data d = dataIter.next();
            if (d.getLength() != 4) continue;
            try {
                int v = mem.getInt(d.getAddress());
                if (v == structBase) {
                    otherSlots.add(d.getAddress().toString());
                    count++;
                }
            } catch (Exception e) {
                // ignore unreadable
            }
        }
        println("Found " + count + " defined-data slots holding this value.");
        for (String s : otherSlots) {
            println("  slot: " + s);
        }

        // For each such slot, find referencing instructions/functions and check for offset 0xa access
        println("\n##### References to each slot #####");
        Set<String> fnsWithOffsetA = new HashSet<>();
        for (String s : otherSlots) {
            Address slotAddr = currentProgram.getAddressFactory().getAddress(s);
            for (Reference ref : getReferencesTo(slotAddr)) {
                Address from = ref.getFromAddress();
                Instruction instr = getInstructionAt(from);
                Function fn = getFunctionContaining(from);
                println("  ref at " + from + " (" + (instr != null ? instr.toString() : "?") + ") in function "
                        + (fn != null ? fn.getName() + "@" + fn.getEntryPoint() : "UNKNOWN"));

                Address a = from;
                for (int i = 0; i < 6 && a != null; i++) {
                    Instruction nextI = getInstructionAt(a);
                    if (nextI == null) break;
                    String is = nextI.toString();
                    if (is.contains("#0xa]")) {
                        println("     >>> OFFSET 0xa ACCESS nearby at " + a + ": " + is);
                        if (fn != null) fnsWithOffsetA.add(fn.getEntryPoint().toString());
                    }
                    a = nextI.getFallThrough();
                }
            }
        }

        println("\n##### Functions found touching offset 0xa via any slot: #####");
        for (String s : fnsWithOffsetA) {
            println("  " + s);
        }
        if (fnsWithOffsetA.isEmpty()) {
            println("  (none found beyond FUN_0808c9c8 itself)");
        }
    }
}
