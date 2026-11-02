import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
import ghidra.program.model.address.*;

public class AVRAsmCapability3 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address a = toAddr(0x080c8a0eL);
        Assembler asm = Assemblers.getAssembler(currentProgram);
        String[] tests = {
            "lsls r3,r3,#0x2", "lsl r3,r3,#0x2",
            "ldr r2,[r2,r3]", "ldr.w r2,[r2,r3]",
            "ldr r2,[r2,r3,lsl #0x2]",
            "movw r2,#0x8a30", "movt r2,#0x080c",
        };
        for (String t : tests) {
            try {
                byte[] b = asm.assembleLine(a, t);
                StringBuilder sb = new StringBuilder();
                for (byte x : b) sb.append(String.format("%02x ", x));
                println("OK   " + String.format("%-28s", t) + " -> " + sb + "(" + b.length + "B)");
            } catch (Exception e) {
                println("FAIL " + String.format("%-28s", t) + " -> " + e.getMessage());
            }
        }
        println("DONE");
    }
}
