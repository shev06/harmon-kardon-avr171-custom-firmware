// Decompile the two functions still not examined from the state 1/2 trace:
//   - 0x0800167c : the real worker behind FUN_0800aa52's "open slot" call
//   - 0x08004c78 : the real worker behind FUN_08005480 (itself called by the
//                  "!!ANAM SOFT!!" resolve wrapper FUN_0800aa9e)
// Goal: find any fseek/lseek-equivalent (offset, whence-style arguments) or
// explicit "+0x10000"-style constant that would explain skipping the header
// of the untrimmed 6 MiB OEM update file.
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class AVRFileOpenWorkerDecompile extends ghidra.app.script.GhidraScript {
    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        String[] addrs = { "0x0800167c", "0x08004c78" };
        for (String s : addrs) {
            decompileOne(s);
        }
    }

    private void decompileOne(String addrStr) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        println("===== " + addrStr + " =====");
        Function fn = getFunctionContaining(addr);
        if (fn == null) {
            ghidra.app.cmd.function.CreateFunctionCmd cmd = new ghidra.app.cmd.function.CreateFunctionCmd(addr);
            cmd.applyTo(currentProgram, new ConsoleTaskMonitor());
            fn = getFunctionContaining(addr);
        }
        if (fn == null) {
            println("  (could not create function; raw disasm:)");
            Address a = addr;
            for (int i = 0; i < 60; i++) {
                ghidra.program.model.listing.Instruction ins = getInstructionAt(a);
                if (ins == null) break;
                println("  " + a + ": " + ins);
                a = ins.getAddress().add(ins.getLength());
            }
            return;
        }
        println("function: " + fn.getEntryPoint() + " - " + fn.getBody().getMaxAddress());
        DecompileResults res = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
        if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("  (decompile failed: " + (res != null ? res.getErrorMessage() : "null") + ")");
        }
    }
}
