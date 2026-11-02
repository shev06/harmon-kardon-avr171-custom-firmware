import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

// Dump raw disassembly with resolved literal-pool values for the exact
// instruction window where FUN_0801074c touches RAM 0x2001bfd8 (the "3600"
// cell), to read the precise consumption logic without wading through the
// huge unrelated IR-dispatch code in the rest of that function.
public class AVRAutoOffDisasmWindow extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Disassembly window 0x080109f0 - 0x08010a80 (around 0x2001bfd8 usage in FUN_0801074c) ===");
        Address a = toAddr(0x080109f0L);
        Address end = toAddr(0x08010a80L);
        while (a.compareTo(end) <= 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { a = a.add(2); continue; }
            StringBuilder extra = new StringBuilder();
            for (ghidra.program.model.symbol.Reference ref : insn.getReferencesFrom()) {
                extra.append(" -> ").append(ref.getToAddress());
            }
            println("  " + a + ": " + insn + extra);
            a = a.add(insn.getLength());
        }
        println("\nDONE");
    }
}
