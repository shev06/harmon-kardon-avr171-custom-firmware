import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class AVRCecStandbyAsm extends ghidra.app.script.GhidraScript {

    @Override
    public void run() throws Exception {
        Address fnAddr = currentProgram.getAddressFactory().getAddress("0x0809b3fc");
        Function fn = getFunctionAt(fnAddr);
        println("##### Full disassembly of FUN_0809b3fc with addresses #####");
        Instruction instr = getInstructionAt(fnAddr);
        Address end = fn.getBody().getMaxAddress();
        while (instr != null && instr.getAddress().compareTo(end) <= 0) {
            println(instr.getAddress() + "  " + instr.toString());
            instr = instr.getNext();
        }

        // Check free space around the existing trampoline area (0x080c89f8 region)
        println("\n##### Scanning for 0xFF free-space run sizes near 0x080c8900-0x080c8a00 #####");
        Memory mem = currentProgram.getMemory();
        Address scanStart = currentProgram.getAddressFactory().getAddress("0x080c8900");
        Address scanEnd = currentProgram.getAddressFactory().getAddress("0x080c8aff");
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

        // Also scan a broader region for any sizable free run near the CEC functions (0x0809bxxx / 0x0808cxxx)
        println("\n##### Broader free-space scan near 0x0809b600-0x0809b900 (end of CEC RX function region) #####");
        Address scanStart2 = currentProgram.getAddressFactory().getAddress("0x0809b600");
        Address scanEnd2 = currentProgram.getAddressFactory().getAddress("0x0809b900");
        a = scanStart2;
        runStart = -1;
        while (a != null && a.compareTo(scanEnd2) <= 0) {
            int b = mem.getByte(a) & 0xff;
            long off = a.subtract(scanStart2);
            if (b == 0xff) {
                if (runStart == -1) runStart = (int) off;
            } else {
                if (runStart != -1) {
                    long len = off - runStart;
                    if (len >= 8) {
                        println("  free run: " + scanStart2.add(runStart) + " .. length " + len);
                    }
                    runStart = -1;
                }
            }
            a = a.add(1);
        }
    }
}
