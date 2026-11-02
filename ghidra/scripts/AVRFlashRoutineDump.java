import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

/** Raw instruction dump of the flash-register literal pool area to find the
 *  real function boundaries (the enclosing routine is not wrapped in a
 *  Function object by existing analysis). */
public class AVRFlashRoutineDump extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getAddress("0x08005f54");
        Address end = currentProgram.getAddressFactory().getAddress("0x080061e0");
        InstructionIterator insIt = currentProgram.getListing().getInstructions(start, true);
        while (insIt.hasNext()) {
            Instruction ins = insIt.next();
            if (ins.getAddress().getOffset() >= end.getOffset()) {
                break;
            }
            println(ins.getAddress() + ": " + ins);
        }

        println("=== FUN_0800aa9e (candidate hash/checksum) ===");
        Address hashAddr = currentProgram.getAddressFactory().getAddress("0x0800aa9e");
        Function hashFn = getFunctionContaining(hashAddr);
        if (hashFn == null) {
            ghidra.app.cmd.function.CreateFunctionCmd cmd = new ghidra.app.cmd.function.CreateFunctionCmd(hashAddr);
            cmd.applyTo(currentProgram, new ConsoleTaskMonitor());
            hashFn = getFunctionContaining(hashAddr);
        }
        if (hashFn != null) {
            println("function: " + hashFn.getEntryPoint() + " body ends " + hashFn.getBody().getMaxAddress());
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults res = decomp.decompileFunction(hashFn, 30, new ConsoleTaskMonitor());
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("decompile failed: " + (res != null ? res.getErrorMessage() : "null"));
            }
        } else {
            println("could not create function at " + hashAddr + "; raw disasm:");
            Address a = hashAddr;
            for (int i = 0; i < 40; i++) {
                Instruction ins = getInstructionAt(a);
                if (ins == null) break;
                println("  " + a + ": " + ins);
                a = ins.getAddress().add(ins.getLength());
            }
        }
    }
}

