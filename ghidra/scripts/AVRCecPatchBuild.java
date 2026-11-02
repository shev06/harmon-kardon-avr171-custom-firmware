import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class AVRCecPatchBuild extends ghidra.app.script.GhidraScript {
    String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);

        Address siteAddr = currentProgram.getAddressFactory().getAddress("0x0809b4bc");
        Address trampAddr = currentProgram.getAddressFactory().getAddress("0x080c89f8");

        println("=== Original bytes at patch site (for verify-before-write) ===");
        Instruction i1 = getInstructionAt(siteAddr);
        Instruction i2 = getInstructionAt(i1.getMaxAddress().next());
        byte[] origSite = new byte[i1.getLength() + i2.getLength()];
        System.arraycopy(i1.getBytes(), 0, origSite, 0, i1.getLength());
        System.arraycopy(i2.getBytes(), 0, origSite, i1.getLength(), i2.getLength());
        println("0x0809b4bc site (" + i1 + " ; " + i2 + ") = " + hex(origSite) + " len=" + origSite.length);

        println("\n=== Patch site replacement ===");
        byte[] siteRepl = asm.assembleLine(siteAddr, "b.w 0x080c89f8");
        println("b.w 0x080c89f8 = " + hex(siteRepl) + " len=" + siteRepl.length);

        println("\n=== Trampoline instructions ===");
        Address a = trampAddr;
        byte[] t1 = asm.assembleLine(a, "beq.w 0x0809b4c4");
        println(a + " beq.w 0x0809b4c4 = " + hex(t1) + " len=" + t1.length);
        a = a.add(t1.length);
        byte[] t2 = asm.assembleLine(a, "movw r0,#0x9678");
        println(a + " movw r0,#0x9678 = " + hex(t2) + " len=" + t2.length);
        a = a.add(t2.length);
        byte[] t3 = asm.assembleLine(a, "movt r0,#0x0809");
        println(a + " movt r0,#0x0809 = " + hex(t3) + " len=" + t3.length);
        a = a.add(t3.length);
        byte[] t4 = asm.assembleLine(a, "ldr r0,[r0,#0x0]");
        println(a + " ldr r0,[r0] = " + hex(t4) + " len=" + t4.length);
        a = a.add(t4.length);
        byte[] t5 = asm.assembleLine(a, "bl 0x0809b394");
        println(a + " bl 0x0809b394 = " + hex(t5) + " len=" + t5.length);
        a = a.add(t5.length);
        byte[] t6 = asm.assembleLine(a, "b.w 0x0809b4d8");
        println(a + " b.w 0x0809b4d8 = " + hex(t6) + " len=" + t6.length);
        a = a.add(t6.length);

        println("\n=== Combined trampoline bytes (for Python patcher) ===");
        byte[][] parts = {t1, t2, t3, t4, t5, t6};
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] full = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, full, off, p.length);
            off += p.length;
        }
        println("trampoline total = " + hex(full) + " len=" + full.length);
        println("trampoline end address = " + a + " (must be <= 0x080c89f8+65 free bytes)");

        println("\n=== Verify literal target ===");
        Address lit = currentProgram.getAddressFactory().getAddress("0x0809b678");
        println("0x0809b678 contents (expected error-string pointer): " +
            currentProgram.getListing().getDataAt(lit));
    }
}
