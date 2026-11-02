import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

// Full disassembly of FUN_080192e2 (the shared power-off handler) with addresses,
// plus a free-space scan near it, to design a patch that redirects its two
// "FUN_08019638()" (full/deep shutdown) call sites to a safe trampoline instead.
public class AVRPowerOffHandlerAsm extends ghidra.app.script.GhidraScript {

    @Override
    public void run() throws Exception {
        Address fnAddr = currentProgram.getAddressFactory().getAddress("0x080192e2");
        Function fn = getFunctionAt(fnAddr);
        println("##### Full disassembly of FUN_080192e2 with addresses #####");
        Instruction instr = getInstructionAt(fnAddr);
        Address end = fn.getBody().getMaxAddress();
        while (instr != null && instr.getAddress().compareTo(end) <= 0) {
            println(instr.getAddress() + "  " + instr.toString());
            instr = instr.getNext();
        }

        // Also disassemble the sibling FUN_08019272 (power-toggle) for comparison, since it
        // shares nearly identical gating logic and its own direct FUN_08019638 call sites.
        println("\n##### Full disassembly of FUN_08019272 with addresses #####");
        Address fnAddr2 = currentProgram.getAddressFactory().getAddress("0x08019272");
        Function fn2 = getFunctionAt(fnAddr2);
        if (fn2 != null) {
            Instruction instr2 = getInstructionAt(fnAddr2);
            Address end2 = fn2.getBody().getMaxAddress();
            while (instr2 != null && instr2.getAddress().compareTo(end2) <= 0) {
                println(instr2.getAddress() + "  " + instr2.toString());
                instr2 = instr2.getNext();
            }
        }

        // Scan for free space (0xFF runs) near this function for a trampoline.
        println("\n##### Free-space scan 0x08019600-0x08019700 #####");
        Memory mem = currentProgram.getMemory();
        Address scanStart = currentProgram.getAddressFactory().getAddress("0x08019600");
        Address scanEnd = currentProgram.getAddressFactory().getAddress("0x080196ff");
        Address a = scanStart;
        int runStart = -1;
        while (a != null && a.compareTo(scanEnd) <= 0) {
            int b = mem.getByte(a) & 0xff;
            long off = a.subtract(scanStart);
            if (b == 0xff) {
                if (runStart == -1) runStart = (int) off;
            } else {
                if (runStart != -1) {
                    println("  free run: " + scanStart.add(runStart) + " .. length " + (off - runStart));
                    runStart = -1;
                }
            }
            a = a.add(1);
        }
        if (runStart != -1) {
            println("  free run continues to scan end from " + scanStart.add(runStart));
        }
    }
}
