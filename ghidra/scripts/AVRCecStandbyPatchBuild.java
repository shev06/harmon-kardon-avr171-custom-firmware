import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class AVRCecStandbyPatchBuild extends ghidra.app.script.GhidraScript {

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);
        Memory mem = currentProgram.getMemory();

        Address patchSite = currentProgram.getAddressFactory().getAddress("0x0809b44a");
        Address trampoline = currentProgram.getAddressFactory().getAddress("0x080c8a0e");

        Instruction origInstr = getInstructionAt(patchSite);
        println("Original instruction at patch site: " + origInstr);
        byte[] origBytes = new byte[origInstr.getLength()];
        mem.getBytes(patchSite, origBytes);
        println("Original site bytes (" + origBytes.length + "): " + hex(origBytes));

        byte[] freeCheck = new byte[16];
        mem.getBytes(trampoline, freeCheck);
        println("Trampoline area before patch (should be all ff): " + hex(freeCheck));

        println("\n=== Trampoline instructions (assembled, NOT written to program) ===");
        Address a = trampoline;
        byte[] t1 = asm.assembleLine(a, "bl 0x0808c9c8");
        println(a + " bl 0x0808c9c8 = " + hex(t1) + " len=" + t1.length);
        a = a.add(t1.length);
        byte[] t2 = asm.assembleLine(a, "bl 0x080192e2");
        println(a + " bl 0x080192e2 = " + hex(t2) + " len=" + t2.length);
        a = a.add(t2.length);
        byte[] t3 = asm.assembleLine(a, "b.w 0x0809b44e");
        println(a + " b.w 0x0809b44e = " + hex(t3) + " len=" + t3.length);
        a = a.add(t3.length);

        println("\nTotal trampoline length: " + a.subtract(trampoline) + " bytes");
        println("Combined trampoline bytes: " + hex(t1) + hex(t2) + hex(t3));

        println("\n=== Patch-site replacement (assembled, NOT written to program) ===");
        byte[] siteRepl = asm.assembleLine(patchSite, "bl 0x080c8a0e");
        println(patchSite + " bl 0x080c8a0e = " + hex(siteRepl) + " len=" + siteRepl.length);

        println("\nDone.");
    }
}
