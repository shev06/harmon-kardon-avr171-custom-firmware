import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.listing.Instruction;

// Independent cross-check: use Ghidra's own assembler to produce "BL 0x080c8a1a"
// at each of the 2 new call-site addresses, and compare against the
// hand-computed encodings, exactly as the original patch's derivation did.
public class AVRShutdownGapBLVerify extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);
        long[] addrs = { 0x080119d0L, 0x08011a1eL };
        for (long a : addrs) {
            Address addr = toAddr(a);
            byte[] bytes = asm.assembleLine(addr, "bl 0x080c8a1a");
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) hex.append(String.format("%02x", b));
            println("Ghidra-assembled BL from " + addr + " to 0x080c8a1a -> " + hex.toString());
        }
        // Also show current (pre-patch) instruction + bytes at both sites for the record
        for (long a : addrs) {
            Address addr = toAddr(a);
            Instruction insn = getInstructionAt(addr);
            byte[] cur = new byte[4];
            currentProgram.getMemory().getBytes(addr, cur);
            StringBuilder hex = new StringBuilder();
            for (byte b : cur) hex.append(String.format("%02x", b));
            println("Current instruction at " + addr + ": " + insn + "   bytes=" + hex.toString());
        }
        println("\nDONE_BL_VERIFY");
    }
}
