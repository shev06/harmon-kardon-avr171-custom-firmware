// Force-create Function objects over the two update-orchestrator windows so they
// can be decompiled, then print the decompilation (or, if decompilation fails,
// raw disassembly) looking specifically for how the flash target address and
// source data pointer are derived before calls into the confirmed flash driver
// (FLASH_EraseSector=0x0800adcc, FLASH_ProgramWord=0x0800ae4a, ProgramByte=0x0800aeaa).
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.ConsoleTaskMonitor;

public class AVROrchestratorDecompile extends GhidraScript {
    private DecompInterface decomp;

    @Override
    protected void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        long[][] windows = {
            { 0x08005c00L, 0x08006300L }, // MCU update orchestrator
            { 0x08007800L, 0x08008100L }  // BCO update orchestrator
        };

        for (long[] w : windows) {
            Address start = currentProgram.getAddressFactory().getAddress(String.format("0x%08x", w[0]));
            Address end = currentProgram.getAddressFactory().getAddress(String.format("0x%08x", w[1]));
            println("##### WINDOW " + start + " - " + end + " #####");
            forceFunctionsAndDecompile(start, end);
        }
    }

    private void forceFunctionsAndDecompile(Address start, Address end) throws Exception {
        Address cur = start;
        while (cur != null && cur.getOffset() < end.getOffset()) {
            Instruction ins = getInstructionAt(cur);
            if (ins == null) {
                cur = cur.add(2);
                continue;
            }
            Function fn = getFunctionContaining(cur);
            if (fn == null) {
                // Try to create a function here.
                CreateFunctionCmd cmd = new CreateFunctionCmd(cur);
                boolean ok = cmd.applyTo(currentProgram, new ConsoleTaskMonitor());
                if (ok) {
                    fn = getFunctionContaining(cur);
                }
            }
            if (fn != null) {
                println("--- function " + fn.getEntryPoint() + " (" + fn.getName() + ") ---");
                DecompileResults res = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    println(res.getDecompiledFunction().getC());
                } else {
                    println("  (decompile failed: " + (res != null ? res.getErrorMessage() : "null result") + ")");
                    // fall back to raw disasm of this function body
                    Address a = fn.getEntryPoint();
                    Address fend = fn.getBody().getMaxAddress();
                    while (a != null && a.getOffset() <= fend.getOffset()) {
                        Instruction i2 = getInstructionAt(a);
                        if (i2 == null) break;
                        println("    " + a + ": " + i2.toString());
                        a = i2.getAddress().add(i2.getLength());
                    }
                }
                Address body = fn.getBody().getMaxAddress();
                cur = body.add(2);
            } else {
                // Could not make a function; skip ahead past this instruction.
                cur = ins.getAddress().add(ins.getLength());
            }
        }
    }
}
