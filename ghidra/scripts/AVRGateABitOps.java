import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

// Precise raw disasm around the two 0x2001c030 write sites inside
// FUN_08019638 (full shutdown) and FUN_08019378 (the reset/resume routine),
// to see exactly which bit(s) each clears/sets.
public class AVRGateABitOps extends ghidra.app.script.GhidraScript {
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
        dump("FUN_08019638 site #1 (around 0x080199b2-0x080199c0)", 0x0801999aL, 0x080199c4L);
        dump("FUN_08019638 site #2 (around 0x080199ee-0x08019a08)", 0x080199deL, 0x08019a10L);
        dump("FUN_08019378 site (around 0x080194a6-0x080194b6)", 0x08019490L, 0x080194c0L);
        println("\nDONE_BITOPS");
    }
}
