import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

// Raw disasm dump around FUN_08064ede's bit1 set/clear operations on the
// candidate-same-cell flag, to directly confirm (by reading the literal
// pool value referenced) whether this really is RAM 0x2001c030.
public class AVRFun64edeBitDump extends ghidra.app.script.GhidraScript {
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
        dump("Around 0x0806513a (first set/clear cluster)", 0x08065120L, 0x08065160L);
        dump("Around 0x080651c4 (second set/clear cluster)", 0x080651b0L, 0x080651e4L);
        dump("Around 0x08064f74 (earlier bit op, FUN_08064ede)", 0x08064f60L, 0x08064f80L);
        dump("Around 0x08065164/0x080651ea (orrs #0x80 sites)", 0x08065160L, 0x08065170L);
        println("\nDONE_64EDE_BITDUMP");
    }
}
