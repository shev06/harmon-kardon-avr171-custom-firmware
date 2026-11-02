import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class AVRAssemblerValidate extends ghidra.app.script.GhidraScript {

    String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x ", x));
        return sb.toString().trim();
    }

    void roundTrip(Assembler asm, String addrStr, String mnemonic) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Instruction insn = getInstructionAt(a);
        byte[] orig = insn.getBytes();
        byte[] assembled = asm.assembleLine(a, mnemonic);
        boolean match = java.util.Arrays.equals(orig, assembled);
        println(addrStr + " | mnemonic=\"" + mnemonic + "\" | orig=[" + hex(orig) +
            "] | assembled=[" + hex(assembled) + "] | MATCH=" + match);
    }

    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);

        println("=== Context check ===");
        Address a1 = currentProgram.getAddressFactory().getAddress("0x08044dc4");
        Address a2 = currentProgram.getAddressFactory().getAddress("0x080c89b4");
        AssemblyPatternBlock ctx1 = asm.getContextAt(a1);
        AssemblyPatternBlock ctx2 = asm.getContextAt(a2);
        println("context @0x08044dc4 (known Thumb code) = " + ctx1);
        println("context @0x080c89b4 (free space)        = " + ctx2);

        println("\n=== Round-trip validation: re-assemble known instructions, compare to original bytes ===");
        roundTrip(asm, "0x08044de8", "add r0,sp,#0x0");
        roundTrip(asm, "0x08044df4", "bl 0x08077bac");
        roundTrip(asm, "0x08044e08", "ldr.w r1,[sp,#0x400]");
        roundTrip(asm, "0x08044e2a", "mov r1,r8");
        roundTrip(asm, "0x08044e2e", "adds r0,r0,r2");
        roundTrip(asm, "0x08044dc4", "push {r0,r1,r2,r4,r5,r6,r7,r8,r9,r10,r11,lr}");
        roundTrip(asm, "0x08044ed2", "pop.w {r4,r5,r6,r7,r8,r9,r10,r11,pc}");

        println("\n=== New-instruction-form tests at free-space address (no original to compare against) ===");
        byte[] cbz = asm.assembleLine(a2, "cbz r0,0x080c89cc");
        println("0x080c89b4 | cbz r0,0x080c89cc | bytes=[" + hex(cbz) + "] | len=" + cbz.length);

        Address a3 = currentProgram.getAddressFactory().getAddress("0x080c89f4");
        byte[] bw = asm.assembleLine(a3, "b.w 0x08044e34");
        println("0x080c89f4 | b.w 0x08044e34 | bytes=[" + hex(bw) + "] | len=" + bw.length);

        // Also test the forms we need for loading param_2/param_3 from new stack offsets
        // (same instruction form as the known-good 0x400 case, just different immediate).
        byte[] ldrP2 = asm.assembleLine(a2, "ldr.w r0,[sp,#0x404]");
        println("ldr.w r0,[sp,#0x404] | bytes=[" + hex(ldrP2) + "] | len=" + ldrP2.length);
        byte[] ldrP3 = asm.assembleLine(a2, "ldr.w r0,[sp,#0x408]");
        println("ldr.w r0,[sp,#0x408] | bytes=[" + hex(ldrP3) + "] | len=" + ldrP3.length);

        byte[] nop = asm.assembleLine(a2, "nop");
        println("nop | bytes=[" + hex(nop) + "] | len=" + nop.length);

        byte[] bwEntry = asm.assembleLine(currentProgram.getAddressFactory().getAddress("0x08044e24"), "b.w 0x080c89b4");
        println("0x08044e24 | b.w 0x080c89b4 (entry-hook replacement) | bytes=[" + hex(bwEntry) + "] | len=" + bwEntry.length);
    }
}
