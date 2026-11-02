import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

// Fresh-reimport verification of the no-op power-off fix: confirm the
// trampoline at 0x080c8a1a now disassembles as "bx lr" + NOPs (no RAM writes
// at all), and confirm the 3 call sites in FUN_080192e2/FUN_08019272 still
// call this same address (unchanged call sites, only the callee body changed).
public class AVRPowerOffNoOpVerify extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Raw disassembly of trampoline at 0x080c8a1a (should be bx lr + NOPs) ===");
        Address a = toAddr(0x080c8a1aL);
        Address end = toAddr(0x080c8a36L);
        while (a.compareTo(end) < 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { println("  " + a + ": [no instruction]"); a = a.add(2); continue; }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        println("\n=== FUN_080192e2 decompile (call sites should still target 0x080c8a1a) ===");
        Function f1 = getFunctionAt(toAddr(0x080192e2L));
        DecompileResults r1 = decompiler.decompileFunction(f1, 60, monitor);
        println(r1.decompileCompleted() ? r1.getDecompiledFunction().getC() : "[failed]");

        println("\n=== FUN_08019272 decompile ===");
        Function f2 = getFunctionAt(toAddr(0x08019272L));
        DecompileResults r2 = decompiler.decompileFunction(f2, 60, monitor);
        println(r2.decompileCompleted() ? r2.getDecompiledFunction().getC() : "[failed]");

        println("\n=== Sanity: FUN_08019638 (full shutdown) unchanged ===");
        Function f3 = getFunctionAt(toAddr(0x08019638L));
        DecompileResults r3 = decompiler.decompileFunction(f3, 60, monitor);
        println(r3.decompileCompleted() ? "[decompiled OK, " + r3.getDecompiledFunction().getC().split("\n").length + " lines]" : "[failed]");

        decompiler.dispose();
        println("\nDONE");
    }
}
