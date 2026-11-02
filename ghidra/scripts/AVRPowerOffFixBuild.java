import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

// Builds the universal power-off fix: a shared trampoline that performs the SAME
// safe "fade/deferral" action FUN_080192e2 already does in its safe branch
// (*0x2001c2b6 = 100; *0x2001bfd8 = 0xe10;) instead of calling FUN_08019638
// (the deep/full shutdown routine that goes network-dark). Redirects all 3
// known "bl 0x08019638" call sites reachable from the shared power-off/toggle
// handlers (2 in FUN_080192e2, 1 in FUN_08019272) to this trampoline.
public class AVRPowerOffFixBuild extends ghidra.app.script.GhidraScript {

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);
        Memory mem = currentProgram.getMemory();

        Address trampoline = currentProgram.getAddressFactory().getAddress("0x080c8a1a");

        // Confirm trampoline area is free.
        byte[] freeCheck = new byte[32];
        mem.getBytes(trampoline, freeCheck);
        println("Trampoline area before patch (should be all ff): " + hex(freeCheck));

        println("\n=== Trampoline instructions (assembled, NOT written to program) ===");
        Address a = trampoline;
        String[] lines = {
            "movw r0,#0xc2b6",
            "movt r0,#0x2001",
            "movs r1,#0x64",
            "strb r1,[r0,#0x0]",
            "movw r0,#0xbfd8",
            "movt r0,#0x2001",
            "movw r1,#0xe10",
            "str r1,[r0,#0x0]",
            "bx lr",
        };
        StringBuilder combined = new StringBuilder();
        for (String line : lines) {
            byte[] enc = asm.assembleLine(a, line);
            println(a + "  " + line + "  = " + hex(enc) + " len=" + enc.length);
            combined.append(hex(enc));
            a = a.add(enc.length);
        }
        println("\nTotal trampoline length: " + a.subtract(trampoline) + " bytes");
        println("Combined trampoline bytes: " + combined.toString());

        println("\n=== Patch-site originals + replacements ===");
        String[] sites = {"0x0801930e", "0x08019348", "0x08019294"};
        for (String siteStr : sites) {
            Address site = currentProgram.getAddressFactory().getAddress(siteStr);
            Instruction orig = getInstructionAt(site);
            byte[] origBytes = new byte[orig.getLength()];
            mem.getBytes(site, origBytes);
            println(site + "  ORIG: " + orig + "  bytes=" + hex(origBytes) + " len=" + origBytes.length);

            byte[] repl = asm.assembleLine(site, "bl 0x080c8a1a");
            println(site + "  NEW : bl 0x080c8a1a = " + hex(repl) + " len=" + repl.length);
            if (repl.length != origBytes.length) {
                println("  !!!! LENGTH MISMATCH, cannot do a drop-in replacement here");
            }
        }

        println("\nDone.");
    }
}
