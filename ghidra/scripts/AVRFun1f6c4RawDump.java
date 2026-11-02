import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

// Raw disasm of FUN_0801f6c4 in full, to resolve the EXACT bit-test polarity
// (tst/and + beq/bne is unambiguous, unlike the decompiler's signed-shift idiom).
public class AVRFun1f6c4RawDump extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== RAW DISASM FUN_0801f6c4 ===");
        Address a = toAddr(0x0801f6c4L);
        ghidra.program.model.listing.Function fn = getFunctionAt(a);
        Address end = fn.getBody().getMaxAddress();
        while (a.compareTo(end) <= 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { a = a.add(2); continue; }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }
        println("\nDONE_1F6C4_RAWDUMP");
    }
}
