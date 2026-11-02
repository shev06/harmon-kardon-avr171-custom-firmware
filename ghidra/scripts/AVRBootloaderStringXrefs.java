import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Finds references to each bootloader UI string, decompiles (and if that
 * fails, disassembles) the containing function, to locate the USB handler,
 * flash writer, and the "!!ANAM SOFT!!" signature check.
 */
public class AVRBootloaderStringXrefs extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] strings = {
            "0x0800d158", "0x0800d1c8", "0x0800d1dc", "0x0800d1f0", "0x0800d204",
            "0x0800d218", "0x0800d22c", "0x0800d240", "0x0800d254", "0x0800d268",
            "0x0800d27c", "0x0800d290", "0x0800d2b8", "0x0800d2d8", "0x0800d318",
            "0x0800d348"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<Address> seenFns = new LinkedHashSet<>();

        for (String s : strings) {
            Address strAddr = currentProgram.getAddressFactory().getAddress(s);
            println("\n########## string @ " + strAddr + " ##########");
            boolean any = false;
            for (Reference ref : getReferencesTo(strAddr)) {
                any = true;
                Address from = ref.getFromAddress();
                Function fn = getFunctionContaining(from);
                if (fn == null) {
                    println("  xref from " + from + " (no containing function)");
                    continue;
                }
                println("  xref from " + from + " in " + fn.getEntryPoint() + " " + fn.getName());
                if (!seenFns.add(fn.getEntryPoint())) {
                    continue;
                }
                DecompileResults r = decompiler.decompileFunction(fn, 60, monitor);
                if (r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    println("  --- decompiled " + fn.getName() + " ---");
                    println(r.getDecompiledFunction().getC());
                } else {
                    println("  --- decompile failed, raw disasm of " + fn.getName() +
                        " (" + fn.getBody().getNumAddresses() + " bytes) ---");
                    InstructionIterator insIt =
                        currentProgram.getListing().getInstructions(fn.getBody(), true);
                    while (insIt.hasNext()) {
                        Instruction ins = insIt.next();
                        println("    " + ins.getAddress() + ": " + ins);
                    }
                }
            }
            if (!any) {
                println("  (no references found)");
            }
        }
        decompiler.dispose();
    }
}
