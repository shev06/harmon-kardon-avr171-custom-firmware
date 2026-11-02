import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

// Validates the patched firmware: disassembles the entry-hook site and the new
// trampoline, and decompiles the function containing the hook to eyeball the
// resulting logical behavior.
public class AVRPatchValidate extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void disasmRange(String label, String startStr, String endStr) throws Exception {
        println("\n=== " + label + " (" + startStr + " .. " + endStr + ") ===");
        Address start = currentProgram.getAddressFactory().getAddress(startStr);
        Address end = currentProgram.getAddressFactory().getAddress(endStr);
        Instruction insn = getInstructionAt(start);
        if (insn == null) insn = currentProgram.getListing().getInstructionAfter(start);
        while (insn != null && insn.getAddress().compareTo(end) <= 0) {
            byte[] bytes = insn.getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) hex.append(String.format("%02x ", b));
            println(insn.getAddress() + " [" + hex.toString().trim() + "] " + insn.toString());
            insn = insn.getNext();
        }
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        disasmRange("Entry hook site", "0x08044e20", "0x08044e34");
        disasmRange("New trampoline", "0x080c89b4", "0x080c89f8");

        Address entry = currentProgram.getAddressFactory().getAddress("0x08044dc4");
        Function fn = getFunctionContaining(entry);
        println("\n=== Decompile of function containing the hook (" + fn.getName() + " @ " + fn.getEntryPoint() + ") ===");
        println("Function body ranges: " + fn.getBody());
        DecompileResults r = decompiler.decompileFunction(fn, 60, monitor);
        if (r.decompileCompleted()) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("[decompile failed: " + r.getErrorMessage() + "]");
        }

        // Is the trampoline recognized as part of the same function, or a separate one?
        Address trampAddr = currentProgram.getAddressFactory().getAddress("0x080c89b4");
        Function trampFn = getFunctionContaining(trampAddr);
        println("\nFunction containing trampoline address: " +
            (trampFn == null ? "none/undefined" : trampFn.getName() + " @ " + trampFn.getEntryPoint()));

        decompiler.dispose();
    }
}
