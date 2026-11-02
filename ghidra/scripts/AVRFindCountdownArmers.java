import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.Memory;

// Resolve the actual RAM targets of DAT_08012244 and DAT_08012248 (the two
// countdown bytes in FUN_08011910 whose expiry calls FUN_08019638 directly,
// bypassing our existing patch), then scan the ENTIRE firmware for every
// instruction that WRITES a nonzero value to those RAM addresses (i.e. who
// arms these countdowns), plus resolve DAT_08011d28 (the gate byte) and
// decompile FUN_08060c64 (called when DAT_08012248 reaches 0x19).
public class AVRFindCountdownArmers extends ghidra.app.script.GhidraScript {

    long readPtrAt(long litPoolAddr) throws Exception {
        Memory mem = currentProgram.getMemory();
        byte[] b = new byte[4];
        mem.getBytes(toAddr(litPoolAddr), b);
        long v = (b[0] & 0xffL) | ((b[1] & 0xffL) << 8) | ((b[2] & 0xffL) << 16) | ((b[3] & 0xffL) << 24);
        return v;
    }

    void findWriters(String label, long ramTarget) {
        println("\n=== Writers to " + label + " (RAM target 0x" + Long.toHexString(ramTarget) + ") ===");
        Address target = toAddr(ramTarget);
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int count = 0;
        while (it.hasNext()) {
            Instruction insn = it.next();
            String mnem = insn.getMnemonicString();
            if (!(mnem.startsWith("STR") || mnem.startsWith("str"))) continue;
            // Check if any operand references our target address (direct or via scalar add)
            Object[] resultObjs = insn.getResultObjects();
            boolean hit = false;
            for (Address refAddr : insn.getReferencesFrom() != null ? new Address[0] : new Address[0]) {}
            // Use reference manager properly
            for (ghidra.program.model.symbol.Reference ref : insn.getReferencesFrom()) {
                if (ref.getToAddress() != null && ref.getToAddress().equals(target)) {
                    hit = true;
                }
            }
            if (hit) {
                count++;
                println("  " + insn.getAddress() + ": " + insn + "   [in " + getFunctionContaining(insn.getAddress()) + "]");
            }
        }
        println("total writers found: " + count);
    }

    @Override
    public void run() throws Exception {
        // DAT_08012244 / DAT_08012248 / DAT_08011d28 are literal-pool labels; Ghidra
        // resolves these to pointers stored at those addresses pointing to RAM.
        long ptr244 = readPtrAt(0x08012244L);
        long ptr248 = readPtrAt(0x08012248L);
        long ptrGate = readPtrAt(0x08011d28L);
        println("DAT_08012244 literal pool -> RAM " + String.format("0x%x", ptr244));
        println("DAT_08012248 literal pool -> RAM " + String.format("0x%x", ptr248));
        println("DAT_08011d28 literal pool -> RAM " + String.format("0x%x", ptrGate));

        findWriters("DAT_08012244", ptr244);
        findWriters("DAT_08012248", ptr248);
        findWriters("DAT_08011d28 (gate)", ptrGate);

        println("\n=== Decompile FUN_08060c64 (called when DAT_08012248 counts down to 0x19) ===");
        ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
        decompiler.openProgram(currentProgram);
        ghidra.program.model.listing.Function f = getFunctionAt(toAddr(0x08060c64L));
        if (f == null) f = getFunctionContaining(toAddr(0x08060c64L));
        if (f != null) {
            ghidra.app.decompiler.DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
            if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            else println("[failed: " + r.getErrorMessage() + "]");
        } else {
            println("[function not found at 08060c64]");
        }
        decompiler.dispose();

        println("\nDONE");
    }
}
