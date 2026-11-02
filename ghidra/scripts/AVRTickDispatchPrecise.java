import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

// Precise raw disassembly of FUN_08011910's handling of BOTH countdown cells
// (0x2001c2b5 and 0x2001c2b6) side by side, to nail down the EXACT condition
// under which the 0x2001c2b5 expiry calls FUN_080192e2 (safe) vs FUN_08019638
// (direct/unconditional full shutdown) -- this is the crux of the whole
// mechanism and must not be inferred from a lossy decompile.
public class AVRTickDispatchPrecise extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Raw disasm 0x08011990-0x08011a40 (FUN_08011910 body around both countdowns) ===");
        Address a = toAddr(0x08011990L);
        Address end = toAddr(0x08011a40L);
        while (a.compareTo(end) < 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { a = a.add(2); continue; }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }
        println("\nDONE_DISASM");
    }
}
