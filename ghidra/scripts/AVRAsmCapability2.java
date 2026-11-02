import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
import ghidra.program.model.address.*;

public class AVRAsmCapability2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address a = toAddr(0x080c8a0eL);
        Assembler asm = Assemblers.getAssembler(currentProgram);
        String[] tests = {
            "mul r3,r0,r3", "muls r3,r3,r0",
            "subs r3,r3,r2", "adds r1,r1,#1",
            "cmp r3,r2", "cmp r1,#0x64",
            "blt 0x080c8a20", "bge 0x080c8a20", "beq 0x080c8a20", "bne 0x080c8a20",
            "ldrb r3,[r3,#0x0]", "ldrb.w r3,[r3,#0x0]",
            "strb r1,[r0,#0x0]",
            "movs r1,#0x0", "movs r3,#0x1",
            "b.w 0x080c8a20", "b 0x080c8a20",
            "adr r2,0x0804b038",
            "bx lr", "bl 0x080192e2",
            "and r3,r3,#0x10", "ands r3,r3,#0x10",
            "ldrb r3,[r3]",
        };
        for (String t : tests) {
            try {
                byte[] b = asm.assembleLine(a, t);
                StringBuilder sb = new StringBuilder();
                for (byte x : b) sb.append(String.format("%02x ", x));
                println("OK   " + String.format("%-22s", t) + " -> " + sb + "(" + b.length + "B)");
            } catch (Exception e) {
                println("FAIL " + String.format("%-22s", t) + " -> " + e.getMessage());
            }
        }
        println("DONE");
    }
}
