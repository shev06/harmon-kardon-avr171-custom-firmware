// Find references TO the literal pool slots that hold the ANAM string pointer
// and the adjacent FLASH_CR-like literal, to locate the actual LDR instructions
// that read them (not just the pointer storage itself).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class AVRAnamXref extends GhidraScript {
    @Override
    protected void run() throws Exception {
        long[] slots = { 0x080069d0L, 0x080069d4L };
        for (long slotAddr : slots) {
            Address slot = currentProgram.getAddressFactory().getAddress(String.format("0x%08x", slotAddr));
            println("=== references TO pool slot " + slot + " ===");
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(slot);
            int count = 0;
            while (it.hasNext()) {
                Reference ref = it.next();
                Address from = ref.getFromAddress();
                println("  from " + from + " type=" + ref.getReferenceType());
                // print context: a few instructions around 'from'
                Address ctxStart = from.subtract(16);
                Address cur = ctxStart;
                for (int i = 0; i < 12 && cur != null; i++) {
                    Instruction ins = getInstructionAt(cur);
                    if (ins != null) {
                        String marker = cur.equals(from) ? " <<<<" : "";
                        println("    " + cur + ": " + ins.toString() + marker);
                        cur = ins.getAddress().add(ins.getLength());
                    } else {
                        cur = cur.add(2);
                    }
                    if (cur != null && cur.getOffset() > from.add(16).getOffset()) break;
                }
                count++;
            }
            println("  total refs: " + count);
        }

        // Also dump raw disassembly just before 0x080069d0 to see the end of the
        // preceding function and confirm where the pool starts.
        println("=== disasm 0x08006980-0x080069d0 ===");
        Address a = currentProgram.getAddressFactory().getAddress("0x08006980");
        Address end = currentProgram.getAddressFactory().getAddress("0x080069d0");
        while (a != null && a.getOffset() < end.getOffset()) {
            Instruction ins = getInstructionAt(a);
            if (ins != null) {
                println("  " + a + ": " + ins.toString());
                a = ins.getAddress().add(ins.getLength());
            } else {
                byte b0 = getByte(a);
                println("  " + a + ": .byte 0x" + String.format("%02x", b0 & 0xff) + " (data)");
                a = a.add(1);
            }
        }
    }
}
