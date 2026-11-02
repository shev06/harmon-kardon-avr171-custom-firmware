import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

// Independent re-validation of the REBASED volume/mute fix (STRINGS_BASE now
// 0x080c8a38, after the universal power-off fix's trampoline) against a
// completely fresh import of the scratch test file.
public class AVRVolMuteVerifyV2 extends GhidraScript {
    DecompInterface decomp;

    private static final long TABLE_BASE = 0x080c8b60L;
    private static final long VOL_CODE = 0x080c8cf4L;
    private static final long MUTE_CODE = 0x080c8d22L;
    private static final long MUTE_CODE_END = 0x080c8d58L;

    private void decompileFn(String label, long addr) throws Exception {
        Address a = toAddr(addr);
        Function f = getFunctionAt(a);
        if (f == null) {
            disassemble(a);
            f = createFunction(a, "FN_" + Long.toHexString(addr));
        }
        println("=== " + label + " @ " + a + " func=" + f);
        DecompileResults res = decomp.decompileFunction(f, 60, monitor);
        if (res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("  decompile failed: " + res.getErrorMessage());
        }
    }

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.openProgram(currentProgram);

        disassemble(toAddr(0x0804ad00L));
        Function dispatcherFn = getFunctionContaining(toAddr(0x0804ae70L));
        if (dispatcherFn == null) {
            dispatcherFn = createFunction(toAddr(0x0804ad00L), "FUN_dispatcher");
        }
        println("=== Dispatcher function @ " + dispatcherFn.getEntryPoint() + " ===");
        DecompileResults res = decomp.decompileFunction(dispatcherFn, 60, monitor);
        if (res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("FAILED: " + res.getErrorMessage());
        }

        decompileFn("Volume trampoline", VOL_CODE);
        decompileFn("Mute trampoline", MUTE_CODE);

        println("\n=== Raw disassembly: volume trampoline ===");
        Listing listing = currentProgram.getListing();
        for (long addr = VOL_CODE; addr < MUTE_CODE; ) {
            Instruction ins = listing.getInstructionAt(toAddr(addr));
            if (ins == null) { addr += 2; continue; }
            println(String.format("%08x  %s", addr, ins.toString()));
            addr += ins.getLength();
        }
        println("\n=== Raw disassembly: mute trampoline ===");
        for (long addr = MUTE_CODE; addr < MUTE_CODE_END; ) {
            Instruction ins = listing.getInstructionAt(toAddr(addr));
            if (ins == null) { addr += 2; continue; }
            println(String.format("%08x  %s", addr, ins.toString()));
            addr += ins.getLength();
        }

        println("\n=== Full string table dump (all 101 entries) ===");
        int mismatches = 0;
        for (int p = 0; p <= 100; p++) {
            long tableEntryAddr = TABLE_BASE + (p * 4L);
            int strAddr = currentProgram.getMemory().getInt(toAddr(tableEntryAddr));
            byte[] buf = new byte[4];
            currentProgram.getMemory().getBytes(toAddr(strAddr & 0xFFFFFFFFL), buf);
            StringBuilder sb = new StringBuilder();
            for (byte b : buf) { if (b == 0) break; sb.append((char) b); }
            String expected = Integer.toString(p);
            boolean ok = sb.toString().equals(expected);
            if (!ok) {
                mismatches++;
                println("  percent=" + p + " table_entry_addr=0x" + Integer.toHexString(strAddr) + " -> \"" + sb + "\" expected=\"" + expected + "\" [MISMATCH]");
            }
        }
        println("String table check: " + (101 - mismatches) + "/101 correct, " + mismatches + " mismatches");

        decomp.dispose();
        println("\nDONE");
    }
}
