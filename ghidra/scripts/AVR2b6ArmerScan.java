import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

// Find every writer of RAM 0x2001c2b6 (the second tick-dispatcher countdown
// cell) to determine what arms it (sets it nonzero) -- to establish whether
// it is reachable from the CEC/button power-request path, or is an
// unrelated feature (e.g. a sleep timer) that should not be touched.
public class AVR2b6ArmerScan extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        long target = 0x2001c2b6L;
        println("=== Scanning for all literal-pool slots whose constant == 0x" + Long.toHexString(target) + " ===");

        Memory mem = currentProgram.getMemory();
        java.util.List<Address> poolSlots = new java.util.ArrayList<>();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            long startOff = start.getOffset();
            long endOff = end.getOffset();
            for (long a = startOff; a + 4 <= endOff; a += 4) {
                try {
                    Address addr = toAddr(a);
                    int b0 = mem.getByte(addr) & 0xFF;
                    int b1 = mem.getByte(addr.add(1)) & 0xFF;
                    int b2 = mem.getByte(addr.add(2)) & 0xFF;
                    int b3 = mem.getByte(addr.add(3)) & 0xFF;
                    long val = (long)(b0 | (b1 << 8) | (b2 << 16)) | ((long)b3 << 24);
                    if (val == target) {
                        poolSlots.add(addr);
                    }
                } catch (Exception e) { /* skip unmapped */ }
            }
        }
        println("Found " + poolSlots.size() + " pool slots containing 0x" + Long.toHexString(target));

        println("\n=== Writers (load pool -> store, with the value/op immediately before) ===");
        for (Address poolAddr : poolSlots) {
            ghidra.program.model.symbol.ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(poolAddr);
            while (refs.hasNext()) {
                ghidra.program.model.symbol.Reference r = refs.next();
                Address from = r.getFromAddress();
                Instruction loadInsn = getInstructionAt(from);
                if (loadInsn == null) continue;
                Instruction cur = loadInsn.getNext();
                Instruction valInsn = null;
                for (int i = 0; i < 6 && cur != null; i++, cur = cur.getNext()) {
                    String mnem = cur.getMnemonicString();
                    if (mnem.equals("movs") || mnem.equals("mov") || mnem.equals("movw")
                            || mnem.equals("subs") || mnem.equals("adds")) {
                        valInsn = cur;
                    }
                    if (mnem.startsWith("strb") || mnem.startsWith("str")) {
                        Function fn = getFunctionContaining(from);
                        println("  WRITE: load@" + from + " val=[" + (valInsn != null ? valInsn.toString() : "?")
                                + "] store@" + cur.getAddress() + ": " + cur
                                + "   [in " + (fn != null ? fn.getName() + "@" + fn.getEntryPoint() : "?") + "]");
                    }
                    if (mnem.startsWith("bl") || mnem.startsWith("b.w") || mnem.startsWith("bx")) break;
                }
            }
        }
        println("\nDONE_2B6_ARMER_SCAN");
    }
}
