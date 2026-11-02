import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

// Exhaustive whole-firmware scan for every instruction that WRITES to RAM
// 0x2001c030 (the single master flag found to gate: (a) whether CEC/button
// power requests do anything in FUN_0802d230, and (b) whether the tick
// dispatcher's deferred 0x2001c2b5 countdown calls the safe FUN_080192e2
// or goes straight to unconditional FUN_08019638 full shutdown).
//
// This cannot rely on Ghidra's reference manager (DAT_* symbols are backed by
// literal-pool loads at many different addresses across the firmware, each
// its own distinct "reference", and Ghidra does not auto-correlate them to
// the same resolved RAM cell). Instead we disassemble every instruction in
// the executable code sections and pattern-match for the two-instruction
// idiom: `ldr.w rX,[POOL]` (where POOL's stored constant == 0x2001c030)
// immediately followed by a `strb`/`str` using rX as the base register.
public class AVRGateAWriterScan extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        long target = 0x2001c030L;
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
        for (Address p : poolSlots) {
            println("  pool slot: " + p);
        }

        println("\n=== For each pool slot, find the full read-modify-write idiom and report the EXACT bit op ===");
        for (Address poolAddr : poolSlots) {
            ghidra.program.model.symbol.ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(poolAddr);
            while (refs.hasNext()) {
                ghidra.program.model.symbol.Reference r = refs.next();
                Address from = r.getFromAddress();
                Instruction loadInsn = getInstructionAt(from);
                if (loadInsn == null) continue;
                // Collect the next few instructions as a window, looking for:
                // ldrb rY,[rX] ; <bitop> rY,rY,#imm ; ldr.w rX,[pool] ; strb rY,[rX]
                Instruction cur = loadInsn.getNext();
                Instruction bitopInsn = null;
                for (int i = 0; i < 6 && cur != null; i++, cur = cur.getNext()) {
                    String mnem = cur.getMnemonicString();
                    if (mnem.equals("ands") || mnem.equals("orrs") || mnem.equals("bic")
                            || mnem.equals("movs") || mnem.equals("mov") || mnem.equals("eors")) {
                        bitopInsn = cur;
                    }
                    if (mnem.startsWith("strb") || mnem.startsWith("str")) {
                        Function fn = getFunctionContaining(from);
                        println("  WRITE: load@" + from + " bitop=[" + (bitopInsn != null ? bitopInsn.toString() : "?")
                                + "] store@" + cur.getAddress() + ": " + cur
                                + "   [in " + (fn != null ? fn.getName() + "@" + fn.getEntryPoint() : "?") + "]");
                    }
                    if (mnem.startsWith("bl") || mnem.startsWith("b.w") || mnem.startsWith("bx")) break;
                }
            }
        }
        println("\nDONE_SCAN");
    }
}
