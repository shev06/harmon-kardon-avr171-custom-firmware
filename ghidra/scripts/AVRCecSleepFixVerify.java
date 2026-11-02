import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

// Fresh-reimport verification of the "CEC standby == button/network power-off" fix.
// Dumps instruction listings for every patched site and decompiles FUN_0802d230
// (CEC key-action dispatcher) so the new control flow can be read directly.
public class AVRCecSleepFixVerify extends ghidra.app.script.GhidraScript {
    private void dump(String title, long from, long to) throws Exception {
        println("=== " + title + " [" + Long.toHexString(from) + ".." + Long.toHexString(to) + ") ===");
        Address a = toAddr(from);
        Address end = toAddr(to);
        while (a.compareTo(end) < 0) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) {
                byte b = getByte(a);
                println("  " + a + ": [no instruction] byte=" + String.format("%02x", b & 0xff));
                a = a.add(1);
                continue;
            }
            println("  " + a + ": " + insn);
            a = a.add(insn.getLength());
        }
    }

    private void decomp(DecompInterface d, long addr) throws Exception {
        Function f = getFunctionAt(toAddr(addr));
        println("\n=== decompile " + Long.toHexString(addr) + " ===");
        if (f == null) { println("[no function at address]"); return; }
        DecompileResults r = d.decompileFunction(f, 90, monitor);
        println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "[decompile failed]");
    }

    @Override
    public void run() throws Exception {
        dump("case 4 gate-B-clear block (expect bl FUN_080192e2 + nops, then b)", 0x0802d2f4L, 0x0802d342L);
        dump("case 0x20 gate-B-clear block (expect bl FUN_080192e2 + nops, then b)", 0x0802d38cL, 0x0802d3e0L);
        dump("restored call site 1 in FUN_080192e2/FUN_08019272 (expect bl FUN_08019638)", 0x08019290L, 0x0801929cL);
        dump("restored call site 2 (expect bl FUN_08019638)", 0x0801930aL, 0x08019316L);
        dump("restored call site 3 (expect bl FUN_08019638)", 0x08019344L, 0x08019350L);
        dump("CEC additive hook in FUN_0809b3fc (expect bl 0x080c8a0e)", 0x0809b442L, 0x0809b458L);
        dump("cave trampoline 0x080c8a0e (additive hook body)", 0x080c8a0eL, 0x080c8a1aL);
        dump("erased old no-op trampoline 0x080c8a1a..0x080c8a38 (expect no instructions, bytes ff)", 0x080c8a1aL, 0x080c8a24L);

        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        decomp(d, 0x0802d230L);
        decomp(d, 0x080192e2L);
        decomp(d, 0x08019272L);
        d.dispose();
        println("\nDONE");
    }
}
