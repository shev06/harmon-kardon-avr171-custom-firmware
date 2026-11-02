// Isolate which arithmetic instructions this program's loaded language actually
// supports for assembleLine, testing each independently (avoid one failure
// aborting the whole batch) and at a known-Thumb address.
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class AVRAsmCapability extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Language ID: " + currentProgram.getLanguageID());
        Address a = toAddr(0x080c8a0eL); // known Thumb trampoline address from a prior successful patch
        Instruction nearby = currentProgram.getListing().getInstructionAt(a);
        println("Existing instruction/context at that addr: " + nearby);

        Assembler asm = Assemblers.getAssembler(currentProgram);
        String[] tests = {
            "MULS r3,r0,r3", "muls r3,r0,r3",
            "UDIV r3,r3,r0", "udiv r3,r3,r0",
            "SDIV r3,r3,r0",
            "MOVW r3,#0xc290", "movw r3,#0xc290",
            "MOVT r3,#0x2001", "movt r3,#0x2001",
            "MOV.W r3,#0xc290",
            "SUBS r3,r3,r2", "ADDS r1,r1,#1",
            "CMP r3,r2", "BLT 0x080c8a20",
            "LDRB r3,[r3,#0x0]",
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
