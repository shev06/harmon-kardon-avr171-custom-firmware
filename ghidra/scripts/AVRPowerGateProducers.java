import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

// Finds every literal-pool copy (anywhere in flash) of the RAM pointer held at each of a
// list of known flash literal slots (the gating variables read by FUN_080192e2), then
// decompiles every distinct function that references any of those copies, so we can see
// who WRITES to these RAM cells (bit3/bit7 of DAT_08019cf4, bit0 of DAT_08019c68, etc.)
// across the whole image, not just the one function we already know reads them.
public class AVRPowerGateProducers extends ghidra.app.script.GhidraScript {

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // label -> flash literal slot address (known from FUN_080192e2's decompile)
        String[][] targets = {
            {"countdown DAT_0801962c", "0x0801962c"},
            {"gate DAT_08019c68 (bit0 tested)", "0x08019c68"},
            {"fade DAT_08019c6c", "0x08019c6c"},
            {"fade DAT_08019c70", "0x08019c70"},
            {"flag DAT_08019c74 (bit7 cleared)", "0x08019c74"},
            {"flag DAT_08019cf4 (bit3/bit7 tested)", "0x08019cf4"},
            {"outer gate DAT_08019354 (bit1 tested)", "0x08019354"},
        };

        Set<String> allFnsDone = new HashSet<>();

        for (String[] t : targets) {
            String label = t[0];
            Address litSlot = currentProgram.getAddressFactory().getAddress(t[1]);
            int ramPtr;
            try {
                ramPtr = mem.getInt(litSlot);
            } catch (Exception e) {
                println("!! could not read literal at " + litSlot + " : " + e);
                continue;
            }
            println("\n########## " + label + "  (slot " + litSlot + " -> RAM 0x" + Integer.toHexString(ramPtr) + ") ##########");

            // Find every other 4-byte defined-data slot anywhere holding this same RAM pointer value.
            Set<Address> copies = new LinkedHashSet<>();
            var dataIter = currentProgram.getListing().getDefinedData(true);
            while (dataIter.hasNext()) {
                Data d = dataIter.next();
                if (d.getLength() != 4) continue;
                try {
                    int v = mem.getInt(d.getAddress());
                    if (v == ramPtr) {
                        copies.add(d.getAddress());
                    }
                } catch (Exception e) { /* ignore */ }
            }
            println("Found " + copies.size() + " literal-pool copies of this RAM pointer.");

            // For each copy, find referencing functions.
            Set<Function> fns = new LinkedHashSet<>();
            for (Address slotAddr : copies) {
                for (Reference ref : getReferencesTo(slotAddr)) {
                    Function fn = getFunctionContaining(ref.getFromAddress());
                    if (fn != null) fns.add(fn);
                }
            }
            println("Referenced from " + fns.size() + " distinct functions: ");
            for (Function fn : fns) {
                println("  " + fn.getName() + "@" + fn.getEntryPoint());
            }

            // Decompile each one (skip ones we've already dumped for a previous target this run).
            for (Function fn : fns) {
                String key = fn.getEntryPoint().toString();
                if (allFnsDone.contains(key)) {
                    println("\n--- (already shown above) " + fn.getName() + "@" + fn.getEntryPoint() + " ---");
                    continue;
                }
                allFnsDone.add(key);
                DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
                println("\n--- " + fn.getName() + "@" + fn.getEntryPoint() + " ---");
                if (res != null && res.decompileCompleted()) {
                    println(res.getDecompiledFunction().getC());
                } else {
                    println("(decompile failed)");
                }
            }
        }
    }
}
