import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class AVRPatchPrep extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void rawDisasm(String label, String startStr, int count) throws Exception {
        println("\n=== " + label + " (raw disasm, " + count + " insns from " + startStr + ") ===");
        Address start = currentProgram.getAddressFactory().getAddress(startStr);
        Instruction insn = getInstructionAt(start);
        if (insn == null) insn = currentProgram.getListing().getInstructionAfter(start);
        int n = 0;
        while (insn != null && n < count) {
            byte[] bytes = insn.getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) hex.append(String.format("%02x ", b));
            println(insn.getAddress() + " [" + hex.toString().trim() + "] " + insn.toString());
            insn = insn.getNext();
            n++;
        }
    }

    void decompileAt(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("[no function]"); return; }
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        println("function: " + f.getEntryPoint() + " body ends " + f.getBody().getMaxAddress());
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("[decompile failed: " + r.getErrorMessage() + "]");
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        rawDisasm("FUN_08044dc4 entry", "0x08044dc4", 10);

        decompileAt("FUN_08077bac (strlen-like helper)", "0x08077bac");
        decompileAt("FUN_08077c00 (strcat-like helper)", "0x08077c00");
        decompileAt("FUN_08044834 (called with no visible args in FUN_08044dc4)", "0x08044834");

        // Confirm nothing branches into the *middle* of FUN_08044dc4 (only the entry).
        Address entry = currentProgram.getAddressFactory().getAddress("0x08044dc4");
        Function fn = getFunctionContaining(entry);
        println("\n=== References landing anywhere inside FUN_08044dc4's body (" +
            fn.getBody().getMinAddress() + "-" + fn.getBody().getMaxAddress() + ") ===");
        Address a2 = fn.getBody().getMinAddress();
        Address end = fn.getBody().getMaxAddress();
        while (a2 != null && a2.compareTo(end) <= 0) {
            for (Reference ref : getReferencesTo(a2)) {
                println("  " + a2 + " <- referenced from " + ref.getFromAddress() + " (" + ref.getReferenceType() + ")");
            }
            a2 = a2.add(1);
        }

        // Confirm free-space block is all 0xFF right at our chosen injection address.
        Address freeStart = currentProgram.getAddressFactory().getAddress("0x080c89b4");
        println("\n=== First 32 bytes at free-space injection site 0x080c89b4 ===");
        byte[] buf = new byte[32];
        currentProgram.getMemory().getBytes(freeStart, buf);
        StringBuilder hex = new StringBuilder();
        for (byte b : buf) hex.append(String.format("%02x ", b));
        println(hex.toString());

        decompiler.dispose();
    }
}
