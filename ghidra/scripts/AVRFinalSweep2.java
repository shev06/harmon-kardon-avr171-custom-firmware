import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;

/** Follow-up micro-sweep: confirm fseek() identity, check trampoline reuse,
 *  and decompile the state-6 cleanup calls + CEC audio-status source. */
public class AVRFinalSweep2 extends ghidra.app.script.GhidraScript {
    private void decompileAt(String label, String addrStr) throws Exception {
        println("\n=== decompile " + label + " (" + addrStr + ") ===");
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function fn = getFunctionContaining(a);
        if (fn == null) {
            ghidra.app.cmd.function.CreateFunctionCmd cmd = new ghidra.app.cmd.function.CreateFunctionCmd(a);
            cmd.applyTo(currentProgram, new ConsoleTaskMonitor());
            fn = getFunctionContaining(a);
        }
        if (fn == null) {
            println("could not create function at " + a);
            return;
        }
        println("function: " + fn.getEntryPoint() + " body ends " + fn.getBody().getMaxAddress());
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
        if (res != null && res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("decompile failed: " + (res != null ? res.getErrorMessage() : "null"));
        }
    }

    @Override
    public void run() throws Exception {
        decompileAt("fseek candidate FUN_0800ab00", "0x0800ab00");

        println("\n=== callers of FUN_080062f0 (jump-to-app trampoline) ===");
        Address tramp = currentProgram.getAddressFactory().getAddress("0x080062f0");
        for (Reference reference : getReferencesTo(tramp)) {
            Function rf = getFunctionContaining(reference.getFromAddress());
            println("  " + reference.getFromAddress() + " " + reference.getReferenceType() +
                (rf == null ? "" : " in " + rf.getEntryPoint() + " " + rf.getName()));
        }

        decompileAt("state-6 cleanup A", "0x08006554");
        decompileAt("state-6 cleanup B", "0x080065c4");
        decompileAt("state-6 bit-set helper", "0x08006f4c");
        decompileAt("CEC audio-status source", "0x0802d174");
    }
}
