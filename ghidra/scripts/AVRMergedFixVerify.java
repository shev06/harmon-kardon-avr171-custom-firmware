import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

// Fresh-reimport verification of the MERGED deliverable: both the power-off
// no-op fix (must still be bx lr) AND the volume/mute fix (patch sites must
// now call their trampolines) must be simultaneously correct.
public class AVRMergedFixVerify extends ghidra.app.script.GhidraScript {
    private DecompInterface decompiler;

    private void dumpFunctionContaining(long addr) throws Exception {
        Function f = getFunctionContaining(toAddr(addr));
        if (f == null) {
            println("  [no function contains 0x" + Long.toHexString(addr) + "]");
            return;
        }
        println("  containing function: " + f.getName() + " @ " + f.getEntryPoint());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "[decompile failed]");
    }

    @Override
    public void run() throws Exception {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        println("=== 1) Power-off trampoline at 0x080c8a1a (must still be bx lr, no-op) ===");
        Address a = toAddr(0x080c8a1aL);
        Address end = toAddr(0x080c8a36L);
        while (a.compareTo(end) < 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { println("  " + a + ": [no instruction]"); a = a.add(2); continue; }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }

        println("\n=== 2) Volume/mute patch site #1 (0x0804ae70) and its containing function ===");
        dumpFunctionContaining(0x0804ae70L);

        println("\n=== 3) Volume/mute patch site #2 (0x0804ae8e) and its containing function ===");
        dumpFunctionContaining(0x0804ae8eL);

        println("\n=== 4) Disassembly of new volmute trampoline code (0x080c8a38-0x080c8d58) ===");
        Address b = toAddr(0x080c8a38L);
        Address bend = toAddr(0x080c8d58L);
        while (b.compareTo(bend) < 0) {
            Instruction insn = getInstructionAt(b);
            if (insn == null) { b = b.add(2); continue; }
            println("  " + b + ": " + insn);
            b = b.add(insn.getLength());
        }

        println("\n=== 5) Sanity: FUN_08019638 (full shutdown) still OK ===");
        Function f3 = getFunctionAt(toAddr(0x08019638L));
        DecompileResults r3 = decompiler.decompileFunction(f3, 60, monitor);
        println(r3.decompileCompleted() ? "[decompiled OK, " + r3.getDecompiledFunction().getC().split("\n").length + " lines]" : "[failed]");

        decompiler.dispose();
        println("\nDONE");
    }
}
