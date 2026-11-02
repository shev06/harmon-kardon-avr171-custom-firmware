import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

// Resolves the RAM addresses behind DAT_0802dd8c / DAT_0802d9bc / DAT_0802dd88
// / DAT_0802de8c / DAT_0802da94 (new cells found in FUN_0802d230's gateB-false
// branch, never examined before), then exhaustively scans the whole firmware
// for every reader/writer of DAT_0802dd8c (the "set to 100" cell) -- same
// technique as the original countdown-armer scan.
public class AVRSecondCountdownTrace extends ghidra.app.script.GhidraScript {

    private Long resolveLoadTarget(Address insnAddr) {
        // Find the literal pool value loaded into the register used by a
        // nearby ldr/ldrb/strb at insnAddr by reading the PCode HIGH value if
        // available; fallback: scan instruction's scalar operand (the DAT_*
        // symbol itself, if Ghidra already resolved it to a global).
        Instruction insn = getInstructionAt(insnAddr);
        if (insn == null) return null;
        for (int i = 0; i < insn.getNumOperands(); i++) {
            Object[] objs = insn.getOpObjects(i);
            for (Object o : objs) {
                if (o instanceof Address) {
                    return ((Address) o).getOffset();
                }
            }
        }
        return null;
    }

    private void scanWritersReaders(String label, long ramAddr) {
        println("=== Exhaustive scan for RAM 0x" + Long.toHexString(ramAddr) + " (" + label + ") ===");
        Address target = toAddr(ramAddr);
        ghidra.program.model.symbol.ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
        int count = 0;
        while (refs.hasNext()) {
            ghidra.program.model.symbol.Reference r = refs.next();
            Address from = r.getFromAddress();
            Instruction insn = getInstructionAt(from);
            Function fn = getFunctionContaining(from);
            String mnem = insn != null ? insn.toString() : "?";
            println("  " + from + " [" + (fn != null ? fn.getName() + "@" + fn.getEntryPoint() : "?") + "]: " + mnem);
            count++;
        }
        println("  total references: " + count);
    }

    @Override
    public void run() throws Exception {
        // First print the raw disassembly around the known DAT_* usage sites
        // inside FUN_0802d230 so we can read off the literal pool addresses
        // Ghidra resolved for each symbol.
        println("=== Raw disasm 0802d360-0802d3e0 (the gateB-false else branch + both uVar2==4/0x20 sites) ===");
        Address a = toAddr(0x0802d360L);
        Address end = toAddr(0x0802d3e0L);
        while (a.compareTo(end) < 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) { a = a.add(2); continue; }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }

        println("\nDONE_DISASM");
    }
}
