import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

/** Decompile the three helper calls inside FUN_0800aa9e to identify the
 *  actual hash/checksum/CRC algorithm used for update validation. */
public class AVRHashAlgoDecompile extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        long[] targets = { 0x08002494L };
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (long t : targets) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("0x%08x", t));
            Function fn = getFunctionContaining(a);
            if (fn == null) {
                ghidra.app.cmd.function.CreateFunctionCmd cmd = new ghidra.app.cmd.function.CreateFunctionCmd(a);
                cmd.applyTo(currentProgram, new ConsoleTaskMonitor());
                fn = getFunctionContaining(a);
            }
            println("=== " + a + " ===");
            if (fn != null) {
                println("function: " + fn.getEntryPoint() + " - " + fn.getBody().getMaxAddress());
                DecompileResults res = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
                if (res != null && res.decompileCompleted()) {
                    println(res.getDecompiledFunction().getC());
                } else {
                    println("decompile failed: " + (res != null ? res.getErrorMessage() : "null"));
                }
            } else {
                println("could not create function; raw disasm:");
                Address cur = a;
                for (int i = 0; i < 60; i++) {
                    ghidra.program.model.listing.Instruction ins = getInstructionAt(cur);
                    if (ins == null) break;
                    println("  " + cur + ": " + ins);
                    cur = ins.getAddress().add(ins.getLength());
                }
            }
        }
    }
}
