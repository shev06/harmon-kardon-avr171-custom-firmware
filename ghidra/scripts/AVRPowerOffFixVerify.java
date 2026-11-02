import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

// Independent re-validation: decompile the patched FUN_080192e2 and FUN_08019272,
// plus the new shared trampoline, from a completely fresh import of the patched
// .fw file, to confirm all 3 "unsafe" bl 0x08019638 call sites now read as the
// safe fade/deferral action instead, with no unintended side effects elsewhere.
public class AVRPowerOffFixVerify extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void dumpDecompile(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("[no function - raw region]"); return; }
        println("function: " + f.getEntryPoint() + " - " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("[failed: " + r.getErrorMessage() + "]");
    }

    void dumpDisasm(String label, String startStr, int count) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(startStr);
        println("\n--- raw disasm: " + label + " ---");
        Instruction instr = getInstructionAt(a);
        for (int i = 0; i < count && instr != null; i++) {
            println(instr.getAddress() + "  " + instr.toString());
            instr = instr.getNext();
        }
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);
        dumpDecompile("Patched FUN_080192e2 (power-off handler)", "0x080192e2");
        dumpDecompile("Patched FUN_08019272 (power-toggle handler)", "0x08019272");
        dumpDisasm("new shared trampoline @ 0x080c8a1a", "0x080c8a1a", 10);
        dumpDecompile("unchanged deep-shutdown routine (FUN_08019638) - sanity check", "0x08019638");
        println("\n--- raw disasm of all 3 patch sites (confirm correct bl target + fallthrough) ---");
        dumpDisasm("site 1 context", "0x080192f8", 6);
        dumpDisasm("site 2 context", "0x08019336", 5);
        dumpDisasm("site 3 context", "0x08019288", 6);
        decompiler.dispose();
    }
}
