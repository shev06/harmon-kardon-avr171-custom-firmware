// Decompile the small helper functions referenced from the newly-found
// MCU-update orchestrator states 1 and 2 (0x08005d0a window), to pin down:
//   - 0x0800aa52 : called with arg=1 from state 1 -- candidate "open slot 1"
//   - 0x0800aa78 : called with the handle value on the failure path -- candidate "close"
//   - 0x0800aa9e : already partly known (open/use/close wrapper) -- confirm its 3 inner calls
//   - 0x0800ada4 : called conditionally (only when *0x080069d4 is negative) right
//                  before the write-loop state var is reset to 0 -- candidate fseek/rewind
//   - 0x08002e60, 0x08005480, 0x08002efc : the three inner calls made by 0x0800aa9e
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class AVRFileHelperDecompile extends ghidra.app.script.GhidraScript {
    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String[] addrs = {
            "0x0800aa52", "0x0800aa78", "0x0800aa9e", "0x0800ada4",
            "0x08002e60", "0x08005480", "0x08002efc"
        };
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
            for (int i = 0; i < 40; i++) {
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
