// Resolve exact RAM addresses behind DAT_0802d9bc/DAT_0802dcac/DAT_0802de60,
// confirm the "on"/"off" literal flash addresses used by the power branch,
// scan current free flash space in the live patched file region, and test
// whether UDIV/MULS assemble for this processor (needed for volume% math).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.app.plugin.assembler.*;

public class AVRVolMuteResolve extends GhidraScript {
    private void showPtr(String label, long litAddr) throws Exception {
        Memory mem = currentProgram.getMemory();
        int v = mem.getInt(toAddr(litAddr));
        println(label + "  literal-slot@" + String.format("%08x", litAddr) + " -> " + String.format("0x%08x", v));
    }

    @Override
    public void run() throws Exception {
        println("=== Resolving FUN_0802d174's literal pointers ===");
        // addresses of the literal pool DAT_ symbols as seen in decompile
        showPtr("mute/mode flag (DAT_0802d9bc)", 0x0802d9bcL);
        showPtr("standby-like flag (DAT_0802dcac)", 0x0802dcacL);
        showPtr("raw volume byte (DAT_0802de60)", 0x0802de60L);

        println("\n=== Resolving power branch on/off literal addresses ===");
        showPtr("DAT_0804b038 ('on'?)", 0x0804b038L);
        showPtr("DAT_0804b03c ('off'?)", 0x0804b03cL);
        // These are inline string bytes at that flash address (not pointers-to-pointers) --
        // "adr r2,[0x804b03c]" in the power branch loads r2 = the address itself.
        Memory mem = currentProgram.getMemory();
        byte[] onBuf = new byte[4];
        byte[] offBuf = new byte[4];
        mem.getBytes(toAddr(0x0804b038L), onBuf);
        mem.getBytes(toAddr(0x0804b03cL), offBuf);
        println("  raw bytes @0x0804b038: " + bytesToHex(onBuf) + " => \"" + new String(onBuf).trim() + "\"");
        println("  raw bytes @0x0804b03c: " + bytesToHex(offBuf) + " => \"" + new String(offBuf).trim() + "\"");

        println("\n=== Testing UDIV / MULS assembly on this processor ===");
        try {
            Assembler asm = Assemblers.getAssembler(currentProgram);
            Address scratch = toAddr(0x0809b000L); // anywhere code-like, just for assembleLine context
            byte[] b1 = asm.assembleLine(scratch, "UDIV r3, r3, r0");
            println("  UDIV r3,r3,r0 -> " + bytesToHex(b1) + " (" + b1.length + " bytes)");
            byte[] b2 = asm.assembleLine(scratch, "MULS r3, r0, r3");
            println("  MULS r3,r0,r3 -> " + bytesToHex(b2) + " (" + b2.length + " bytes)");
            byte[] b3 = asm.assembleLine(scratch, "MOVW r3, #0xc290");
            println("  MOVW r3,#0xc290 -> " + bytesToHex(b3) + " (" + b3.length + " bytes)");
            byte[] b4 = asm.assembleLine(scratch, "MOVT r3, #0x2001");
            println("  MOVT r3,#0x2001 -> " + bytesToHex(b4) + " (" + b4.length + " bytes)");
        } catch (Exception e) {
            println("  assembly test FAILED: " + e);
        }

        println("DONE");
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x ", x));
        return sb.toString();
    }
}
