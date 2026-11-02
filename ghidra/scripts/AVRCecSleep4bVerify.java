import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

// Fresh-reimport verification of Option 4b r3 ("CEC standby == button/network power-off via cec_sleep_helper";
// the old FUN_0809b3fc "additive power-off" hook is restored to stock and its cave trampolines are erased).
// Everything printed here comes from a FRESH import + auto-analysis of the patched .fw, so it is independent of the
// builder script that produced the bytes.
public class AVRCecSleep4bVerify extends ghidra.app.script.GhidraScript {
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

    private void words(String title, long from, int count) throws Exception {
        println("=== " + title + " ===");
        for (int i = 0; i < count; i++) {
            Address a = toAddr(from + 4L * i);
            Data dd = getDataAt(a);
            println("  " + a + ": 0x" + String.format("%08x", getInt(a)) + "   codeunit=" + (dd == null ? "none/insn" : dd.toString()));
        }
    }

    private void bytesFF(String title, long from, long to) throws Exception {
        println("=== " + title + " [" + Long.toHexString(from) + ".." + Long.toHexString(to) + ") ===");
        int nonFF = 0, withCode = 0;
        StringBuilder sb = new StringBuilder();
        for (long x = from; x < to; x++) {
            Address a = toAddr(x);
            int b = getByte(a) & 0xff;
            if (b != 0xff) nonFF++;
            if (getInstructionAt(a) != null || getDataAt(a) != null && getDataAt(a).isDefined()) withCode++;
            sb.append(String.format("%02x", b));
        }
        println("  bytes=" + sb + "  nonFF=" + nonFF + "  addrsWithDefinedCodeUnit=" + withCode);
    }

    private void refsTo(String title, long addr) throws Exception {
        println("=== references TO " + title + " (" + Long.toHexString(addr) + ") ===");
        Reference[] refs = getReferencesTo(toAddr(addr));
        java.util.List<String> rows = new java.util.ArrayList<>();
        for (Reference r : refs) {
            Function f = getFunctionContaining(r.getFromAddress());
            rows.add(String.format("%s %s in %s", r.getFromAddress(), r.getReferenceType(), f == null ? "(no function)" : f.getName()));
        }
        java.util.Collections.sort(rows);
        for (String s : rows) println("  " + s);
        println("  count=" + rows.size());
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
        Function hf = getFunctionAt(toAddr(0x080c8d58L));
        println("function at helper 0x080c8d58 after fresh auto-analysis: " + (hf == null ? "NONE" : hf.getName() + " body=" + hf.getBody()));

        dump("helper body cec_sleep_helper (code part, expect 48-byte routine ending at 0x080c8d87)", 0x080c8d58L, 0x080c8d88L);
        words("helper literal pool (expect 2001c030, 2001c038, 2001bfb8, 2001c2b5)", 0x080c8d88L, 4);
        dump("case 4 gate-B-clear block (expect bl 0x080c8d58 + nops, then original b)", 0x0802d2f4L, 0x0802d342L);
        dump("case 0x20 gate-B-clear block (expect bl 0x080c8d58 + nops, then original b)", 0x0802d38cL, 0x0802d3e0L);
        dump("restored call site 1 (expect bl 0x08019638)", 0x08019290L, 0x0801929cL);
        dump("restored call site 2 (expect bl 0x08019638)", 0x0801930aL, 0x08019316L);
        dump("restored call site 3 (expect bl 0x08019638)", 0x08019344L, 0x08019350L);
        dump("CEC callback hook in FUN_0809b3fc (r3: expect the STOCK bl 0x0808c9c8 again)", 0x0809b442L, 0x0809b458L);
        dump("CEC Active Source fix cave (untouched by r3; expect ... b.w 0x0809b4d8 ending at 0x080c8a0e)", 0x080c89f8L, 0x080c8a0eL);
        bytesFF("erased cave callback trampoline 0x080c8a0e + old no-op trampoline (expect all ff, no code units)", 0x080c8a0eL, 0x080c8a38L);
        bytesFF("free flash after the helper (expect all ff)", 0x080c8d98L, 0x080c8dc0L);

        refsTo("cec_sleep_helper", 0x080c8d58L);
        refsTo("FUN_080192e2 (power-off request)", 0x080192e2L);
        refsTo("FUN_08019638 (shutdown entry)", 0x08019638L);
        refsTo("FUN_08019272 (button toggle)", 0x08019272L);
        refsTo("erased cave trampoline 0x080c8a0e (expect none)", 0x080c8a0eL);
        refsTo("erased no-op trampoline 0x080c8a1a (expect none)", 0x080c8a1aL);
        refsTo("FUN_0808c9c8 (CEC callback helper; expect only the stock callers in FUN_0809b3fc)", 0x0808c9c8L);

        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        decomp(d, 0x0802d230L);
        decomp(d, 0x080c8d58L);
        decomp(d, 0x080192e2L);
        decomp(d, 0x08019272L);
        decomp(d, 0x0809b3fcL);
        d.dispose();
        println("\nDONE");
    }
}
