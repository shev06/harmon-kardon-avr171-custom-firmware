import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;

/** Combined final-sweep pass covering several remaining open-work items:
 *  (1) write-loop dispatch switch + states 6/7/8 (post-write completion /
 *      reboot trigger) for the recovery-path question;
 *  (2) CEC report functions decompiled fully, to check for any shared
 *      state address with the XML status path;
 *  (3) context around the 3 unverified vector-table candidates;
 *  (4) raw tail disassembly of the TCP:10025 dispatcher for patch-hook design. */
public class AVRFinalSweep extends ghidra.app.script.GhidraScript {
    private void disasmRange(String label, String startStr, String endStr) throws Exception {
        println("\n=== disasm " + label + " (" + startStr + " - " + endStr + ") ===");
        Address start = currentProgram.getAddressFactory().getAddress(startStr);
        Address end = currentProgram.getAddressFactory().getAddress(endStr);
        InstructionIterator insIt = currentProgram.getListing().getInstructions(start, true);
        while (insIt.hasNext()) {
            Instruction ins = insIt.next();
            if (ins.getAddress().getOffset() >= end.getOffset()) {
                break;
            }
            println(ins.getAddress() + ": " + ins);
        }
    }

    private void decompileAt(String label, String addrStr) throws Exception {
        println("\n=== decompile " + label + " (" + addrStr + ") ===");
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function fn = getFunctionContaining(a);
        if (fn == null) {
            ghidra.app.cmd.function.CreateFunctionCmd cmd = new ghidra.app.cmd.function.CreateFunctionCmd(a);
            cmd.applyTo(currentProgram, new ConsoleTaskMonitor());
            fn = getFunctionContaining(a);
        }
        if (fn == null) {
            println("could not create function at " + a);
            return;
        }
        println("function: " + fn.getEntryPoint() + " body ends " + fn.getBody().getMaxAddress());
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
        if (res != null && res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("decompile failed: " + (res != null ? res.getErrorMessage() : "null"));
        }
    }

    private void contextAround(String label, long addr) throws Exception {
        println("\n=== context around candidate " + label + String.format(" 0x%08x", addr) + " ===");
        Address a = currentProgram.getAddressFactory().getAddress(String.format("0x%08x", addr));
        Function fn = getFunctionContaining(a);
        println("containing function: " + (fn == null ? "none" : fn.getEntryPoint() + " " + fn.getName()));
        ghidra.program.model.listing.Data data = getDataContaining(a);
        println("containing data: " + (data == null ? "none" : data.getAddress() + " " + data.getDataType()));
        println("refs TO this address:");
        for (Reference reference : getReferencesTo(a)) {
            Function rf = getFunctionContaining(reference.getFromAddress());
            println("  " + reference.getFromAddress() + " " + reference.getReferenceType() +
                (rf == null ? "" : " in " + rf.getEntryPoint() + " " + rf.getName()));
        }
        // dump raw bytes window
        byte[] buf = new byte[64];
        try {
            currentProgram.getMemory().getBytes(a.subtract(16), buf);
            StringBuilder sb = new StringBuilder();
            for (byte b : buf) sb.append(String.format("%02x ", b));
            println("bytes [addr-16 .. addr+48]: " + sb);
        } catch (Exception e) {
            println("byte read failed: " + e.getMessage());
        }
    }

    @Override
    public void run() throws Exception {
        // (1) write-loop dispatch switch (just before the already-dumped 0x08005f54 window)
        disasmRange("write-loop dispatch switch", "0x08005e72", "0x08005f54");

        // (1b) continue the write-loop disasm past the previous 0x080061e0 cutoff to find
        // state 6/7/8 handlers (post all-sectors-written) and any reboot/reset trigger.
        disasmRange("write-loop states 6-8 continuation", "0x080061e0", "0x080064a0");

        // (2) CEC report functions - full decompile to check RAM addresses touched
        decompileAt("CEC report power status", "0x0804b304");
        decompileAt("CEC report audio status", "0x0804b56e");
        decompileAt("CEC report dispatcher", "0x0804d134");

        // (3) vector-table candidate context
        contextAround("A", 0x0800d050L);
        contextAround("B", 0x080bbe54L);
        contextAround("C", 0x080bc560L);

        // (4) TCP:10025 dispatcher tail - find the final "no match" fallthrough for patch design
        Address dispAddr = currentProgram.getAddressFactory().getAddress("0x08049d90");
        Function dispFn = getFunctionContaining(dispAddr);
        if (dispFn != null) {
            Address tailStart = dispFn.getBody().getMaxAddress().subtract(96);
            println("\n=== dispatcher tail disasm (" + tailStart + " - " + dispFn.getBody().getMaxAddress() + ") ===");
            InstructionIterator insIt = currentProgram.getListing().getInstructions(tailStart, true);
            while (insIt.hasNext()) {
                Instruction ins = insIt.next();
                if (ins.getAddress().getOffset() > dispFn.getBody().getMaxAddress().getOffset()) {
                    break;
                }
                println(ins.getAddress() + ": " + ins);
            }
        } else {
            println("dispatcher function not found at " + dispAddr);
        }
    }
}
