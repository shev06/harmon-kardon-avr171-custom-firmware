import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

// Precise raw disasm context around both 0x2001c2b6 arming sites, to
// determine whether arming is unconditional on every call, or gated.
public class AVR2b6ArmContext extends ghidra.app.script.GhidraScript {
    private void dump(String label, long startAddr, long endAddr) throws Exception {
        println("=== " + label + " ===");
        Address a = toAddr(startAddr);
        Address end = toAddr(endAddr);
        while (a.compareTo(end) < 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { a = a.add(2); continue; }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }
    }

    @Override
    public void run() throws Exception {
        dump("FUN_08019272 arming context (around 0x080192a0)", 0x08019260L, 0x080192b0L);
        dump("FUN_080192e2 arming context (around 0x0801931a)", 0x080192e2L, 0x08019330L);
        println("\nDONE_2B6_ARM_CONTEXT");
    }
}
