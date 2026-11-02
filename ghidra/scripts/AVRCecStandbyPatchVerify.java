import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

// Independent re-validation: decompile the patched FUN_0809b3fc (CEC RX handler)
// and the new trampoline from a completely fresh import of the patched .fw file,
// to confirm the additive fix reads correctly post-patch with no unintended
// side effects on the other CEC opcodes.
public class AVRCecStandbyPatchVerify extends ghidra.app.script.GhidraScript {
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
        dumpDecompile("Patched CEC RX handler (FUN_0809b3fc)", "0x0809b3fc");
        dumpDisasm("new trampoline @ 0x080c8a0e", "0x080c8a0e", 4);
        dumpDecompile("unchanged shared power-off handler (FUN_080192e2) - sanity check", "0x080192e2");
        decompiler.dispose();
    }
}
